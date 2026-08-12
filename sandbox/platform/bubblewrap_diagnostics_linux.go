//go:build linux

package platform

import (
	"bytes"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"unicode"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/sandbox"
)

// Bubblewrap enforces with namespaces and mounts rather than an LSM, so it
// never observes a denial: the kernel fails the syscall and the sandboxed
// program reports it. The prefix varies by program ("cat:", "npm ERR!",
// "/bin/sh: 1: cannot create"); the strerror(3) phrase it ends with does not,
// so matching is anchored on the suffix.
const (
	bubblewrapErrnoEACCES = "Permission denied"
	bubblewrapErrnoEPERM  = "Operation not permitted"
	bubblewrapErrnoEROFS  = "Read-only file system"
	bubblewrapErrnoENOENT = "No such file or directory"
)

var bubblewrapErrnoPhrases = []string{
	bubblewrapErrnoEACCES,
	bubblewrapErrnoEPERM,
	bubblewrapErrnoEROFS,
	bubblewrapErrnoENOENT,
}

// bubblewrapMaxTargetLen bounds a parsed target. The sandboxed process controls
// what reaches stderr, and no path the kernel rejected can exceed PATH_MAX.
const bubblewrapMaxTargetLen = 4096

// bubblewrapVerbs maps the verb a program prefixes to a path onto a violation
// kind. Only verbs that contradict the fallback in bubblewrapViolationKind are
// listed; a read verb would restate it.
//
// When adding an entry, place it ahead of any prefix it extends so the longer
// match wins.
var bubblewrapVerbs = []struct {
	prefix string
	kind   sandbox.ViolationKind
}{
	{"cannot remove ", sandbox.ViolationKindFSDeleteOrRename},
	{"failed to remove ", sandbox.ViolationKindFSDeleteOrRename},
	{"cannot unlink ", sandbox.ViolationKindFSDeleteOrRename},
	{"cannot move ", sandbox.ViolationKindFSDeleteOrRename},
	{"cannot create ", sandbox.ViolationKindFSWrite},
	{"cannot touch ", sandbox.ViolationKindFSWrite},
	{"failed to create symbolic link ", sandbox.ViolationKindFSWrite},
	{"changing ownership of ", sandbox.ViolationKindFSWrite},
	{"changing permissions of ", sandbox.ViolationKindFSWrite},
	{"execvp ", sandbox.ViolationKindExec},
}

// bubblewrapQuotePairs are the quoting styles a program may use to delimit a
// path. Coreutils selects between the ASCII and Unicode forms by locale, so
// both occur in practice; the backtick form is older GNU output.
var bubblewrapQuotePairs = []struct {
	open  string
	close string
}{
	{"‘", "’"},
	{"“", "”"},
	{"`", "'"},
	{"'", "'"},
	{`"`, `"`},
}

// bubblewrapDenial is one stderr line reduced to the facts a sandbox.Violation
// carries.
type bubblewrapDenial struct {
	kind    sandbox.ViolationKind
	target  string
	process string
	rawKind string
	raw     string
}

// parseBubblewrapDenial extracts a denial from a single stderr line, reporting
// false for anything it cannot parse confidently. Most package manager output
// is not a denial, and for an advisory report a false positive costs more than
// a miss.
//
// ENOENT is accepted only for an exec failure, which bwrap itself reports. A
// missing path reported by the sandboxed program cannot be told apart from a
// file that genuinely does not exist.
func parseBubblewrapDenial(line string) (bubblewrapDenial, bool) {
	raw := strings.TrimSpace(line)

	// Some programs terminate the message with a period. Match without it, but
	// keep raw as printed.
	trimmed := strings.TrimRight(raw, ".")

	errno, ok := bubblewrapErrnoSuffix(trimmed)
	if !ok {
		return bubblewrapDenial{}, false
	}

	head := strings.TrimRight(strings.TrimSuffix(trimmed, errno), ": ")
	if head == "" {
		return bubblewrapDenial{}, false
	}

	// Split on colon-space rather than colon: a path may legally contain a
	// colon ("a:b.txt") but effectively never a colon followed by a space.
	fields := strings.Split(head, ": ")
	message := strings.TrimSpace(fields[len(fields)-1])

	kind := bubblewrapViolationKind(message, errno)
	if errno == bubblewrapErrnoENOENT && kind != sandbox.ViolationKindExec {
		return bubblewrapDenial{}, false
	}

	target := bubblewrapExtractTarget(message)
	if !bubblewrapPlausibleTarget(target) {
		return bubblewrapDenial{}, false
	}

	return bubblewrapDenial{
		kind:    kind,
		target:  target,
		process: bubblewrapStripControl(bubblewrapProcess(fields)),
		rawKind: errno,
		raw:     bubblewrapStripControl(raw),
	}, true
}

// bubblewrapErrnoSuffix reports the errno phrase a line ends with; lines
// without one are not denials.
func bubblewrapErrnoSuffix(line string) (string, bool) {
	for _, phrase := range bubblewrapErrnoPhrases {
		if strings.HasSuffix(line, phrase) {
			return phrase, true
		}
	}

	return "", false
}

// bubblewrapViolationKind classifies from the verb the program used. Without a
// recognised verb the operation is inferred: EROFS can only come from a write,
// and a bare "<path>: Permission denied" is a failed open for read.
func bubblewrapViolationKind(message, errno string) sandbox.ViolationKind {
	for _, v := range bubblewrapVerbs {
		if strings.HasPrefix(message, v.prefix) {
			return v.kind
		}
	}

	if errno == bubblewrapErrnoEROFS {
		return sandbox.ViolationKindFSWrite
	}

	return sandbox.ViolationKindFSRead
}

// bubblewrapExtractTarget recovers the path from a message that may carry
// arbitrary prose around it.
func bubblewrapExtractTarget(message string) string {
	if quoted, ok := bubblewrapQuotedTarget(message); ok {
		return quoted
	}

	if idx := strings.LastIndexByte(message, ' '); idx >= 0 {
		return message[idx+1:]
	}

	return message
}

// bubblewrapQuotedTarget returns the innermost quoted region of the message.
// Quoting is the only delimiter a program gives for a path containing spaces,
// and some tools follow the path with prose ("cannot open '/x' for reading"),
// so the search is not anchored to the end. Selecting the latest opening quote
// keeps an unrelated earlier quote from swallowing the path.
func bubblewrapQuotedTarget(message string) (string, bool) {
	bestStart, bestEnd, openLen := -1, -1, 0

	for _, q := range bubblewrapQuotePairs {
		end := strings.LastIndex(message, q.close)
		if end <= 0 {
			continue
		}

		if start := strings.LastIndex(message[:end], q.open); start > bestStart {
			bestStart, bestEnd, openLen = start, end, len(q.open)
		}
	}

	if bestStart < 0 {
		return "", false
	}

	return message[bestStart+openLen : bestEnd], true
}

// bubblewrapPlausibleTarget rejects anything that does not look like a path.
// The trailing token of a line is often prose: without this check the line
// "npm ERR! ... Permission denied" would report "..." as a denied path. A path
// carries a separator or an extension, and at least one letter or digit.
//
// Extensionless bare names in the working directory (Makefile) are consequently
// missed. That is the deliberate side of the trade: a wrong target produces a
// misleading override suggestion, while a missed one only costs a report.
func bubblewrapPlausibleTarget(target string) bool {
	if target == "" || len(target) > bubblewrapMaxTargetLen {
		return false
	}

	if strings.ContainsFunc(target, unicode.IsControl) {
		return false
	}

	if !strings.Contains(target, "/") && !strings.Contains(target, ".") {
		return false
	}

	return strings.ContainsFunc(target, func(r rune) bool {
		return unicode.IsLetter(r) || unicode.IsDigit(r)
	})
}

// bubblewrapProcess recovers the failing program from the leading field. It is
// advisory: programs that do not prefix their name yield "".
func bubblewrapProcess(fields []string) string {
	if len(fields) < 2 {
		return ""
	}

	head := strings.TrimSpace(fields[0])
	if head == "" || strings.ContainsAny(head, " \t") {
		return ""
	}

	return filepath.Base(head)
}

// bubblewrapStripControl removes control characters from a field bound for a
// terminal. Unlike the other drivers' evidence, these fields are written by the
// sandboxed process. Dropping the escape character leaves the rest of any
// sequence as inert text, so it cannot act on the terminal when
// `pmg sandbox explain` renders it.
//
// A target carrying control characters is rejected outright instead, since it
// also feeds an override suggestion the user may copy.
func bubblewrapStripControl(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

// bubblewrapDenialCap bounds the per-run denial buffer. Denials are deduplicated
// before the cap applies, so this caps distinct denials: a process retrying one
// denied path cannot evict a later, different one.
const bubblewrapDenialCap = 512

// bubblewrapMaxLineLen bounds an unterminated line. The sandboxed process
// decides when to emit a newline, so a stream without one must not grow the tap
// indefinitely.
const bubblewrapMaxLineLen = 16 * 1024

// bubblewrapStderrTap is an io.Writer spliced into the sandboxed command's
// stderr. It reassembles lines across writes, since a write carries an arbitrary
// byte range rather than whole lines, and buffers the denials it finds.
//
// Write never reports an error. The tap shares cmd.Stderr with the user's
// terminal through io.MultiWriter, which stops at the first failing writer, so
// failing here would silence the command's own output.
type bubblewrapStderrTap struct {
	mu       sync.Mutex
	partial  []byte
	skipping bool
	denials  []bubblewrapDenial
	seen     map[string]bool
	dropped  bool
}

func newBubblewrapStderrTap() *bubblewrapStderrTap {
	return &bubblewrapStderrTap{seen: make(map[string]bool)}
}

// bubblewrapDenialKey identifies a denial for deduplication: the same kind of
// block on the same target is one denial, however many times a process retries.
func bubblewrapDenialKey(d bubblewrapDenial) string {
	return string(d.kind) + "\x00" + d.target
}

func (t *bubblewrapStderrTap) Write(p []byte) (int, error) {
	n := len(p)

	t.mu.Lock()
	defer t.mu.Unlock()

	for len(p) > 0 {
		idx := bytes.IndexByte(p, '\n')
		if idx < 0 {
			t.buffer(p)
			break
		}

		t.buffer(p[:idx])
		t.flushLine()
		p = p[idx+1:]
	}

	return n, nil
}

// buffer accumulates a line fragment. An over-long line is abandoned rather than
// truncated: a truncated head still ends in the errno phrase and would parse
// into a plausible but wrong target.
//
// Caller must hold t.mu.
func (t *bubblewrapStderrTap) buffer(chunk []byte) {
	if t.skipping {
		return
	}

	if len(t.partial)+len(chunk) > bubblewrapMaxLineLen {
		t.skipping = true
		t.partial = nil
		return
	}

	t.partial = append(t.partial, chunk...)
}

// flushLine records a denial if the accumulated line holds one.
//
// Caller must hold t.mu.
func (t *bubblewrapStderrTap) flushLine() {
	line := string(t.partial)
	t.partial = nil

	if t.skipping {
		t.skipping = false
		return
	}

	denial, ok := parseBubblewrapDenial(line)
	if !ok {
		return
	}

	key := bubblewrapDenialKey(denial)
	if t.seen[key] {
		return
	}

	if len(t.denials) >= bubblewrapDenialCap {
		if !t.dropped {
			t.dropped = true
			log.Warnf("bubblewrap diagnostics: denial buffer full (%d), dropping further denials", bubblewrapDenialCap)
		}
		return
	}

	// seen is marked only on append so it stays bounded by the cap. Its keys
	// carry paths the sandboxed process chose, so growing it unconditionally
	// would reintroduce the memory growth the cap exists to prevent.
	t.seen[key] = true
	t.denials = append(t.denials, denial)
}

// collect flushes any unterminated trailing line and returns the buffered
// denials. Callers invoke it after cmd.Run() has returned, when no further
// writes can race with the flush.
func (t *bubblewrapStderrTap) collect() []bubblewrapDenial {
	t.mu.Lock()
	defer t.mu.Unlock()

	if len(t.partial) > 0 {
		t.flushLine()
	}

	out := make([]bubblewrapDenial, len(t.denials))
	copy(out, t.denials)

	return out
}

// attachDiagnostics splices a stderr tap into cmd for this run. State is
// replaced on every Execute so a reused driver never reports a previous run's
// denials.
//
// The existing writer is wrapped rather than replaced: the caller has already
// pointed stderr at the user's terminal, and the command's own output must
// reach it unchanged.
func (b *bubblewrapSandbox) attachDiagnostics(cmd *exec.Cmd, policy *sandbox.SandboxPolicy) {
	tap := newBubblewrapStderrTap()

	b.tap = tap
	b.policyName = policy.Name

	if cmd.Stderr == nil {
		cmd.Stderr = tap
		return
	}

	cmd.Stderr = io.MultiWriter(cmd.Stderr, tap)
}

// DiagnosticsWriter exposes this run's tap for execution paths that route the
// command's output themselves instead of through cmd.Stderr. A PTY session
// merges stdout and stderr onto the pty master, so the tap sees both; denial
// lines are still selected by their errno suffix.
func (b *bubblewrapSandbox) DiagnosticsWriter() io.Writer {
	if b.tap == nil {
		return nil
	}

	return b.tap
}

// BestEffortViolation reports denials parsed from the sandboxed command's own
// output during the last Execute. Coverage is bounded by what that command
// chose to print, since bubblewrap observes nothing itself; see
// parseBubblewrapDenial for what is and is not recognised.
func (b *bubblewrapSandbox) BestEffortViolation(err error) (*sandbox.ViolationReport, error) {
	if err == nil || b.tap == nil {
		return nil, nil
	}

	denials := b.tap.collect()
	if len(denials) == 0 {
		return nil, nil
	}

	violations := make([]sandbox.Violation, 0, len(denials))
	for _, d := range denials {
		violations = append(violations, sandbox.Violation{
			Kind:      d.kind,
			RawKind:   d.rawKind,
			Target:    d.target,
			Process:   d.process,
			RawLog:    d.raw,
			RuleLabel: summarizeViolation(d.kind, d.target),
		})
	}

	return &sandbox.ViolationReport{
		SandboxName: b.Name(),
		PolicyName:  b.policyName,
		Violations:  violations,
	}, nil
}
