//go:build darwin
// +build darwin

package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/sandbox"
)

const seatbeltLogWindowPadding = 2 * time.Second
const seatbeltMaxQueryWait = 6 * time.Second
const seatbeltCleanFallbackWait = 2 * time.Second
const seatbeltQueryInterval = 250 * time.Millisecond
const seatbeltLogCommandTimeout = 5 * time.Second
const macOSUnifiedLogPath = "/usr/bin/log"

var seatbeltMessagePattern = regexp.MustCompile(`PMG_SBX\|run=([^|]+)\|kind=([^|]+)\|target=([^"\s]*)`)

// seatbeltDenyVerbPattern captures the sandbox-exec denial verb from a raw log
// line such as `Sandbox: node(123) deny(1) file-write-data /path`. The verb is
// used to recover a typed ViolationKind when a denial hit the catch-all
// `(deny default ...)` rule (which only carries `kind=default` in our marker).
var seatbeltDenyVerbPattern = regexp.MustCompile(`\bdeny\(\d+\)\s+(\S+)`)

type seatbeltLogEntry struct {
	EventMessage     string `json:"eventMessage"`
	Process          string `json:"process"`
	ProcessImagePath string `json:"processImagePath"`
}

type seatbeltLogPayload struct {
	RunID  string
	Kind   string
	Target string
}

func parseSeatbeltLogPayload(raw string) (*seatbeltLogPayload, bool) {
	matches := seatbeltMessagePattern.FindStringSubmatch(raw)
	if len(matches) != 4 {
		return nil, false
	}

	target, err := urlQueryUnescape(matches[3])
	if err != nil {
		target = matches[3]
	}

	return &seatbeltLogPayload{
		RunID:  matches[1],
		Kind:   matches[2],
		Target: target,
	}, true
}

func (s *seatbeltSandbox) BestEffortViolation(err error) (*sandbox.ViolationReport, error) {
	if s.logTag == "" || s.startedAt.IsZero() {
		return nil, nil
	}

	// The stream saw the run as it happened, so a clean run trusts a complete
	// stream. A failed run with no denial in the stream still polls the log
	// store below, because the user looks for the cause.
	streamed, complete := s.streamEntries(err)
	if complete {
		if violations := s.runViolations(streamed, err); len(violations) > 0 {
			return s.violationReport(violations), nil
		}
		if err == nil {
			return nil, nil
		}
	}

	// Without a complete stream, PMG polls the log store, because a denial
	// can reach the store late. Each query result is merged with what the
	// stream delivered, so a delivered denial is never lost. A clean run
	// polls for a shorter time. This path is rare, because the stream covers
	// almost every run.
	wait := seatbeltMaxQueryWait
	if err == nil {
		wait = seatbeltCleanFallbackWait
	}
	deadline := time.Now().Add(wait)
	var lastQueryErr error

	for {
		end := time.Now()
		stored, queryErr := s.queryLogs(s.startedAt.Add(-seatbeltLogWindowPadding), end.Add(seatbeltLogWindowPadding))
		if queryErr != nil {
			lastQueryErr = queryErr
		}
		if violations := s.runViolations(mergeSeatbeltEntries(streamed, stored), err); len(violations) > 0 {
			return s.violationReport(violations), nil
		}

		if time.Now().After(deadline) {
			break
		}

		time.Sleep(seatbeltQueryInterval)
	}

	if lastQueryErr != nil {
		return nil, lastQueryErr
	}

	return nil, nil
}

// streamEntries stops the log stream of the run and returns what it
// delivered. A clean run reports no catch-all denials, so the stream returns
// them only for a failed run. complete is false when the run has no stream,
// or when the stream could not confirm that it delivered every denial that
// the run reports. The entries are real denials in both cases.
func (s *seatbeltSandbox) streamEntries(runErr error) (entries []seatbeltLogEntry, complete bool) {
	if s.stream == nil {
		return nil, false
	}

	entries, complete = s.stream.end(runErr != nil)
	s.stream = nil
	return entries, complete
}

// mergeSeatbeltEntries returns the entries of the log store, plus the entries
// of the stream that the store does not have yet. An event that both report
// counts once. The entries of the store stay as they are, so a run that the
// store covers reports the same as before the stream existed.
func mergeSeatbeltEntries(streamed, stored []seatbeltLogEntry) []seatbeltLogEntry {
	inStore := make(map[string]int, len(stored))
	for _, entry := range stored {
		inStore[entry.EventMessage]++
	}

	merged := append([]seatbeltLogEntry(nil), stored...)
	for _, entry := range streamed {
		if inStore[entry.EventMessage] > 0 {
			inStore[entry.EventMessage]--
			continue
		}
		merged = append(merged, entry)
	}

	return merged
}

// runViolations extracts the denials of this run. A clean run keeps only the
// denials of the policy's own deny rules.
func (s *seatbeltSandbox) runViolations(entries []seatbeltLogEntry, runErr error) []sandbox.Violation {
	violations := extractSeatbeltViolations(entries, s.logTag)
	if runErr == nil {
		violations = seatbeltRuleDenials(violations)
	}

	return violations
}

func (s *seatbeltSandbox) violationReport(violations []sandbox.Violation) *sandbox.ViolationReport {
	return &sandbox.ViolationReport{
		SandboxName:   s.Name(),
		PolicyName:    s.policyName,
		CorrelationID: s.logTag,
		Violations:    violations,
	}
}

// seatbeltRuleDenials drops the denials of the catch-all (deny default) rule
// and keeps the denials of the policy's own deny rules. A clean run reports
// only these. Ordinary tools cross the allow-list edge on start, for example
// to register DTrace helpers, read sysctls or look up system services, so the
// catch-all fires on almost every clean run. This leaves a known gap. On a
// clean run, PMG does not report a write that only the catch-all blocks, such
// as one to a shell startup file.
func seatbeltRuleDenials(violations []sandbox.Violation) []sandbox.Violation {
	return slices.DeleteFunc(violations, func(v sandbox.Violation) bool {
		return v.RawKind == seatbeltKindDefault
	})
}

func extractSeatbeltViolations(entries []seatbeltLogEntry, runID string) []sandbox.Violation {
	violations := make([]sandbox.Violation, 0, len(entries))
	for _, entry := range entries {
		payload, ok := parseSeatbeltLogPayload(entry.EventMessage)
		if !ok || payload.RunID != runID || payload.Kind == seatbeltKindSentinel {
			continue
		}

		process := entry.Process
		if process == "" {
			process = entry.ProcessImagePath
		}

		target := extractSeatbeltDeniedPath(entry.EventMessage, payload)
		if target == "" {
			target = payload.Target
		}

		kind := normalizeSeatbeltViolationKind(payload.Kind)
		labelKind := payload.Kind

		// When the deny hit our catch-all `(deny default ...)` rule, the
		// marker only carries `kind=default`. The sandbox-exec preamble in
		// the same log line names the real verb (file-write-data, etc.) so
		// we recover the typed kind from there. This drives accurate
		// primary-violation ranking and `--sandbox-allow` suggestions.
		if kind == sandbox.ViolationKindGenericDeny {
			if inferredKind, inferredLabelKind, ok := inferSeatbeltKindFromRawLog(entry.EventMessage); ok {
				kind = inferredKind
				labelKind = inferredLabelKind
			}
		}

		// Network denial operands are addresses, not paths, so the
		// path-shaped extraction above rejected them; recover the raw token.
		if target == "" && (kind == sandbox.ViolationKindNetworkBind || kind == sandbox.ViolationKindNetworkConnect) {
			target = extractSeatbeltDeniedToken(entry.EventMessage, payload)
		}

		// The lockdown deny marker (target=direct) is authoritative for the
		// human message even when the raw operand is path-shaped (e.g. the
		// mDNSResponder unix socket); Target keeps the denied operand.
		labelTarget := target
		if labelKind == seatbeltKindNetworkOutbound && payload.Target == seatbeltLockdownTargetDirect {
			labelTarget = payload.Target
		}

		violations = append(violations, sandbox.Violation{
			Kind:       kind,
			RawKind:    payload.Kind,
			Target:     target,
			RuleTarget: payload.Target,
			Process:    process,
			RawLog:     strings.TrimSpace(entry.EventMessage),
			RuleLabel:  summarizeSeatbeltViolation(labelKind, labelTarget),
		})
	}

	return violations
}

func normalizeSeatbeltViolationKind(kind string) sandbox.ViolationKind {
	switch kind {
	case "file-read":
		return sandbox.ViolationKindFSRead
	case "file-write":
		return sandbox.ViolationKindFSWrite
	case "file-write-unlink":
		return sandbox.ViolationKindFSDeleteOrRename
	case "process-exec":
		return sandbox.ViolationKindExec
	default:
		return sandbox.ViolationKindGenericDeny
	}
}

// inferSeatbeltKindFromRawLog recovers a typed ViolationKind from the
// sandbox-exec denial verb embedded in raw. It returns the typed kind plus a
// canonical marker name (the one our own rules would emit for the same kind,
// suitable for summarizeSeatbeltViolation). Only verbs that map to kinds
// scoreViolation already understands are recognized; all others fall back to
// (generic_deny, "", false) so the caller keeps the original classification.
func inferSeatbeltKindFromRawLog(raw string) (sandbox.ViolationKind, string, bool) {
	m := seatbeltDenyVerbPattern.FindStringSubmatch(raw)
	if len(m) != 2 {
		return sandbox.ViolationKindGenericDeny, "", false
	}

	verb := m[1]
	switch {
	case verb == "file-write-unlink", verb == "file-write-mount", verb == "file-rename":
		return sandbox.ViolationKindFSDeleteOrRename, "file-write-unlink", true
	case strings.HasPrefix(verb, "file-write"), verb == "file-link", verb == "file-mknod":
		return sandbox.ViolationKindFSWrite, "file-write", true
	case strings.HasPrefix(verb, "file-read"):
		return sandbox.ViolationKindFSRead, "file-read", true
	case strings.HasPrefix(verb, "process-exec"):
		return sandbox.ViolationKindExec, "process-exec", true
	case verb == "network-bind":
		return sandbox.ViolationKindNetworkBind, "network-bind", true
	case verb == seatbeltKindNetworkOutbound:
		return sandbox.ViolationKindNetworkConnect, seatbeltKindNetworkOutbound, true
	}

	return sandbox.ViolationKindGenericDeny, "", false
}

func extractSeatbeltDeniedPath(raw string, payload *seatbeltLogPayload) string {
	last := extractSeatbeltDeniedToken(raw, payload)
	if last == "" || !looksLikeConcretePath(last) {
		return ""
	}

	return last
}

// extractSeatbeltDeniedToken returns the last token of the sandbox-exec
// preamble before our marker — the denial operand. Unlike
// extractSeatbeltDeniedPath it does not require a path shape, so it also
// recovers network addresses such as "local:*:0" or "1.2.3.4:443".
func extractSeatbeltDeniedToken(raw string, payload *seatbeltLogPayload) string {
	if payload == nil {
		return ""
	}

	marker := seatbeltLogMessage(payload.RunID, payload.Kind, payload.Target)
	idx := strings.Index(raw, marker)
	if idx < 0 {
		return ""
	}

	prefix := strings.TrimSpace(raw[:idx])
	if prefix == "" {
		return ""
	}

	fields := strings.Fields(prefix)
	if len(fields) == 0 {
		return ""
	}

	last := strings.TrimSpace(fields[len(fields)-1])
	return strings.Trim(last, "\"',;:()[]{}")
}

// seatbeltRunPredicate selects the unified log entries of one run by the
// marker that its deny rules carry.
func seatbeltRunPredicate(logTag string) string {
	return fmt.Sprintf(`eventMessage CONTAINS "PMG_SBX|run=%s|"`, logTag)
}

func (s *seatbeltSandbox) queryLogs(start, end time.Time) ([]seatbeltLogEntry, error) {
	info, err := os.Stat(macOSUnifiedLogPath)
	if err != nil {
		return nil, fmt.Errorf("macOS unified log CLI not available: %w", err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("macOS unified log CLI not available: %s is a directory", macOSUnifiedLogPath)
	}

	args := []string{
		"show",
		"--style", "json",
		"--start", start.Format("2006-01-02 15:04:05"),
		"--end", end.Format("2006-01-02 15:04:05"),
		"--predicate", seatbeltRunPredicate(s.logTag),
	}

	ctx, cancel := context.WithTimeout(context.Background(), seatbeltLogCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, macOSUnifiedLogPath, args...)

	output, err := cmd.Output()
	if err != nil {
		var stderr bytes.Buffer
		if ee, ok := err.(*exec.ExitError); ok {
			stderr.Write(ee.Stderr)
		}
		return nil, fmt.Errorf("query seatbelt logs: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}

	entries, err := decodeSeatbeltLogEntries(output)
	if err != nil {
		return nil, fmt.Errorf("decode seatbelt logs: %w", err)
	}

	return entries, nil
}

func decodeSeatbeltLogEntries(data []byte) ([]seatbeltLogEntry, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, nil
	}

	var list []seatbeltLogEntry
	if err := json.Unmarshal(trimmed, &list); err == nil {
		return list, nil
	}

	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	entries := []seatbeltLogEntry{}
	for {
		var entry seatbeltLogEntry
		if err := decoder.Decode(&entry); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

func summarizeSeatbeltViolation(kind, target string) string {
	switch kind {
	case "file-read":
		return fmt.Sprintf("read access denied: %s", target)
	case "file-write":
		return fmt.Sprintf("write access denied: %s", target)
	case "file-write-unlink":
		return fmt.Sprintf("rename or unlink denied: %s", target)
	case "process-exec":
		return fmt.Sprintf("process execution denied: %s", target)
	case "network-bind":
		if target == "" {
			return "network bind denied"
		}
		return fmt.Sprintf("network bind denied: %s", target)
	case seatbeltKindNetworkOutbound:
		if target == seatbeltLockdownTargetDirect {
			return "direct network access blocked by network_via_proxy_only — traffic must flow through the PMG proxy (a tool may have ignored HTTP_PROXY/HTTPS_PROXY)"
		}
		if target == "" {
			return "network connect denied"
		}
		return fmt.Sprintf("network connect denied: %s", target)
	default:
		if target == "" {
			return "sandbox denied an operation"
		}
		return fmt.Sprintf("sandbox denied access to %s", target)
	}
}

func looksLikeConcretePath(value string) bool {
	if value == "" {
		return false
	}

	if strings.ContainsAny(value, "*?[]") {
		return false
	}

	return strings.Contains(value, "/") || strings.HasPrefix(value, ".")
}

func urlQueryUnescape(value string) (string, error) {
	unescaped, err := url.QueryUnescape(value)
	if err != nil {
		log.Debugf("seatbelt diagnostics: failed to decode %q: %v", value, err)
		return "", err
	}
	return unescaped, nil
}
