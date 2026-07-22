//go:build linux

package platform

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
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
		if evt.Type == auditSeccompDeny {
			key := string(landlockViolationKind(evt)) + "\x00" + evt.Path
			if seen[key] {
				continue
			}
			seen[key] = true
		}

		s.auditMu.Lock()
		if len(s.auditEvents) < landlockAuditEventCap {
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
// rename, network) fail in-kernel with no userspace signal and never appear
// here. Operational events (namespace_isolation_unavailable, memfd_open_failed)
// are deliberately excluded from the report; they are degradation warnings,
// not denials.
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
		if e.Type != auditSeccompDeny {
			continue
		}

		kind := landlockViolationKind(e.auditEvent)
		key := string(kind) + "\x00" + e.Path
		if seen[key] {
			continue
		}
		seen[key] = true

		violations = append(violations, sandbox.Violation{
			Kind:       kind,
			RawKind:    e.Syscall,
			Target:     e.Path,
			RuleTarget: e.RulePath,
			Process:    e.Comm,
			RawLog:     e.raw,
			RuleLabel:  summarizeLandlockViolation(kind, e.Path),
		})
	}

	return violations
}

func landlockViolationKind(e auditEvent) sandbox.ViolationKind {
	switch e.Syscall {
	case "execve", "execveat":
		return sandbox.ViolationKindExec
	case "openat", "openat2":
		if e.Access == "read" {
			return sandbox.ViolationKindFSRead
		}
		return sandbox.ViolationKindFSWrite
	default:
		return sandbox.ViolationKindGenericDeny
	}
}

func summarizeLandlockViolation(kind sandbox.ViolationKind, target string) string {
	switch kind {
	case sandbox.ViolationKindFSRead:
		return fmt.Sprintf("read access denied: %s", target)
	case sandbox.ViolationKindFSWrite:
		return fmt.Sprintf("write access denied: %s", target)
	case sandbox.ViolationKindExec:
		return fmt.Sprintf("process execution denied: %s", target)
	default:
		if target == "" {
			return "sandbox denied an operation"
		}
		return fmt.Sprintf("sandbox denied access to %s", target)
	}
}
