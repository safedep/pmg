//go:build linux

package platform

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/sandbox"
)

// landlockAuditEventCap bounds the per-run audit event buffer. Deny events
// are deduplicated by (kind, path) at capture time, so this caps DISTINCT
// denials — reaching it means hundreds of different denied targets, itself
// worth the one-time warning below.
const landlockAuditEventCap = 512

// landlockAuditDrainWait bounds how long BestEffortViolation waits for the
// audit reader goroutine to finish. The helper exits before cmd.Run()
// returns, so EOF is normally immediate; the timeout covers the case where
// the helper never connected and Accept is still blocked.
const landlockAuditDrainWait = 2 * time.Second

// capturedAuditEvent pairs a decoded audit event with its original JSON line
// so the violation report can preserve the raw evidence.
type capturedAuditEvent struct {
	auditEvent
	raw string
}

// captureAuditEvents reads newline-delimited auditEvent JSON from the audit
// socket connection and buffers events for BestEffortViolation. Malformed
// lines are skipped; both sides are the same pmg binary so they indicate
// corruption, not version skew.
func (s *landlockSandbox) captureAuditEvents(r io.Reader) {
	scanner := bufio.NewScanner(r)
	seen := make(map[string]bool)
	dropped := false
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}

		var evt auditEvent
		if err := json.Unmarshal(line, &evt); err != nil {
			log.Debugf("landlock diagnostics: skipping malformed audit event: %v", err)
			continue
		}

		// Dedupe deny events before the cap: a tight retry loop on one denied
		// path must not fill the buffer and evict a later distinct denial.
		// seen is marked only on append so it stays bounded by the cap — the
		// keys carry attacker-chosen path bytes, so an unbounded map would
		// reintroduce the memory growth the cap exists to prevent. Once the
		// buffer is full, new distinct denials hit the drop branch (and its
		// one-time warning) instead of growing the map.
		key := ""
		if evt.Type == auditSeccompDeny || evt.Type == auditNetworkDeny {
			key = landlockDenyKey(evt)
			if seen[key] {
				continue
			}
		}

		s.auditMu.Lock()
		if len(s.auditEvents) < landlockAuditEventCap {
			if key != "" {
				seen[key] = true
			}
			s.auditEvents = append(s.auditEvents, capturedAuditEvent{auditEvent: evt, raw: string(line)})
		} else if !dropped {
			dropped = true
			log.Warnf("landlock diagnostics: audit event buffer full (%d), dropping further events", landlockAuditEventCap)
		}
		s.auditMu.Unlock()
	}

	if err := scanner.Err(); err != nil {
		log.Debugf("landlock diagnostics: audit socket read: %v", err)
	}
}

// BestEffortViolation reports seccomp-layer denials captured over the audit
// socket during the last Execute. Only the deny-list layer is observable:
// denials made by the Landlock LSM itself (allow-list boundary, delete or
// rename) fail in-kernel with no userspace signal and never appear here.
// Network lockdown denials do appear — they are supervisor decisions
// (auditNetworkDeny), not kernel Landlock denials. Operational events
// (namespace_isolation_unavailable, memfd_open_failed) are deliberately
// excluded from the report; they are degradation warnings, not denials.
func (s *landlockSandbox) BestEffortViolation(err error) (*sandbox.ViolationReport, error) {
	if err == nil || s.auditDone == nil {
		return nil, nil
	}

	select {
	case <-s.auditDone:
	case <-time.After(landlockAuditDrainWait):
	}

	s.auditMu.Lock()
	events := make([]capturedAuditEvent, len(s.auditEvents))
	copy(events, s.auditEvents)
	s.auditMu.Unlock()

	violations := extractLandlockViolations(events)
	if len(violations) == 0 {
		return nil, nil
	}

	return &sandbox.ViolationReport{
		SandboxName: s.Name(),
		PolicyName:  s.policyName,
		Violations:  violations,
	}, nil
}

// extractLandlockViolations maps seccomp deny events to violations,
// deduplicating identical (kind, target) pairs — a process commonly retries
// a denied open many times.
func extractLandlockViolations(events []capturedAuditEvent) []sandbox.Violation {
	violations := make([]sandbox.Violation, 0, len(events))
	seen := make(map[string]bool, len(events))

	for _, e := range events {
		if e.Type != auditSeccompDeny && e.Type != auditNetworkDeny {
			continue
		}

		key := landlockDenyKey(e.auditEvent)
		if seen[key] {
			continue
		}
		seen[key] = true

		kind := landlockViolationKind(e.auditEvent)

		violations = append(violations, sandbox.Violation{
			Kind:       kind,
			RawKind:    e.Syscall,
			Target:     e.Path,
			RuleTarget: e.RulePath,
			Process:    e.Comm,
			RawLog:     e.raw,
			RuleLabel:  summarizeViolation(kind, e.Path),
		})
	}

	return violations
}

// landlockDenyKey identifies a denial for deduplication: events with the same
// violation kind and target are the same denial. Capture-time dedupe
// (captureAuditEvents) and extract-time dedupe (extractLandlockViolations)
// must agree on this identity, so both use this function.
func landlockDenyKey(e auditEvent) string {
	return string(landlockViolationKind(e)) + "\x00" + e.Path
}

func landlockViolationKind(e auditEvent) sandbox.ViolationKind {
	switch e.Syscall {
	case "execve", "execveat":
		return sandbox.ViolationKindExec
	case "connect", "sendto", "sendmsg":
		return sandbox.ViolationKindNetworkConnect
	}

	kind, ok := pathOpKindForSyscall(e.Syscall)
	if !ok {
		return sandbox.ViolationKindGenericDeny
	}
	switch kind {
	case pathOpOpen:
		if e.Access == "read" {
			return sandbox.ViolationKindFSRead
		}
		return sandbox.ViolationKindFSWrite
	case pathOpRename, pathOpLink, pathOpRemove:
		return sandbox.ViolationKindFSDeleteOrRename
	default:
		return sandbox.ViolationKindFSWrite
	}
}
