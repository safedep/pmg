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
	"strings"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/sandbox"
)

const seatbeltLogWindowPadding = 2 * time.Second
const seatbeltMaxQueryWait = 6 * time.Second
const seatbeltQueryInterval = 250 * time.Millisecond
const seatbeltLogCommandTimeout = 5 * time.Second
const macOSUnifiedLogPath = "/usr/bin/log"

var seatbeltMessagePattern = regexp.MustCompile(`PMG_SBX\|run=([^|]+)\|kind=([^|]+)\|target=([^"\s]*)`)

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
	if err == nil || s.logTag == "" || s.startedAt.IsZero() {
		return nil, nil
	}

	deadline := time.Now().Add(seatbeltMaxQueryWait)
	var lastQueryErr error

	for {
		end := time.Now()
		entries, queryErr := s.queryLogs(s.startedAt.Add(-seatbeltLogWindowPadding), end.Add(seatbeltLogWindowPadding))
		if queryErr != nil {
			lastQueryErr = queryErr
		} else {
			violations := extractSeatbeltViolations(entries, s.logTag)
			if len(violations) > 0 {
				return &sandbox.ViolationReport{
					SandboxName:   s.Name(),
					PolicyName:    s.policyName,
					CorrelationID: s.logTag,
					Violations:    violations,
				}, nil
			}
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

func extractSeatbeltViolations(entries []seatbeltLogEntry, runID string) []sandbox.Violation {
	violations := make([]sandbox.Violation, 0, len(entries))
	for _, entry := range entries {
		payload, ok := parseSeatbeltLogPayload(entry.EventMessage)
		if !ok || payload.RunID != runID {
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

		violations = append(violations, sandbox.Violation{
			Kind:       normalizeSeatbeltViolationKind(payload.Kind),
			RawKind:    payload.Kind,
			Target:     target,
			RuleTarget: payload.Target,
			Process:    process,
			RawLog:     strings.TrimSpace(entry.EventMessage),
			RuleLabel:  summarizeSeatbeltViolation(payload.Kind, target),
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

func extractSeatbeltDeniedPath(raw string, payload *seatbeltLogPayload) string {
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
	last = strings.Trim(last, "\"',;:()[]{}")

	if last == "" || !looksLikeConcretePath(last) {
		return ""
	}

	return last
}

func (s *seatbeltSandbox) queryLogs(start, end time.Time) ([]seatbeltLogEntry, error) {
	info, err := os.Stat(macOSUnifiedLogPath)
	if err != nil {
		return nil, fmt.Errorf("macOS unified log CLI not available: %w", err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("macOS unified log CLI not available: %s is a directory", macOSUnifiedLogPath)
	}

	predicate := fmt.Sprintf(`eventMessage CONTAINS "PMG_SBX|run=%s|"`, s.logTag)
	args := []string{
		"show",
		"--style", "json",
		"--start", start.Format("2006-01-02 15:04:05"),
		"--end", end.Format("2006-01-02 15:04:05"),
		"--predicate", predicate,
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
