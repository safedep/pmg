//go:build linux

package platform

import (
	"path/filepath"
	"strings"

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
// kind. It only classifies: bubblewrapExtractTarget does not consult it, so an
// unlisted verb costs precision on the kind rather than losing the target.
//
// Longer prefixes precede the prefixes they contain so the longest match wins.
var bubblewrapVerbs = []struct {
	prefix string
	kind   sandbox.ViolationKind
}{
	{"cannot remove directory ", sandbox.ViolationKindFSDeleteOrRename},
	{"cannot remove ", sandbox.ViolationKindFSDeleteOrRename},
	{"cannot unlink ", sandbox.ViolationKindFSDeleteOrRename},
	{"cannot rename ", sandbox.ViolationKindFSDeleteOrRename},
	{"cannot move ", sandbox.ViolationKindFSDeleteOrRename},
	{"cannot create ", sandbox.ViolationKindFSWrite},
	{"cannot make directory ", sandbox.ViolationKindFSWrite},
	{"cannot touch ", sandbox.ViolationKindFSWrite},
	{"cannot write ", sandbox.ViolationKindFSWrite},
	{"changing ownership of ", sandbox.ViolationKindFSWrite},
	{"changing permissions of ", sandbox.ViolationKindFSWrite},
	{"cannot open ", sandbox.ViolationKindFSRead},
	{"cannot access ", sandbox.ViolationKindFSRead},
	{"cannot stat ", sandbox.ViolationKindFSRead},
	{"execvp ", sandbox.ViolationKindExec},
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
	trimmed := strings.TrimRight(strings.TrimSpace(line), ".")

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
		process: bubblewrapProcess(fields),
		rawKind: errno,
		raw:     trimmed,
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
// arbitrary prose in front of it. Quoting is the only delimiter a program gives
// for a path containing spaces, so a quoted tail wins; otherwise the path is the
// final whitespace-separated token.
func bubblewrapExtractTarget(message string) string {
	if inner, ok := bubblewrapQuotedTail(message); ok {
		return inner
	}

	if idx := strings.LastIndexByte(message, ' '); idx >= 0 {
		return message[idx+1:]
	}

	return message
}

// bubblewrapQuotedTail returns the contents of a quoted region closing the
// message. GNU tools historically render names as `name' rather than 'name'.
func bubblewrapQuotedTail(message string) (string, bool) {
	if len(message) < 2 {
		return "", false
	}

	body := message[:len(message)-1]

	var open int
	switch message[len(message)-1] {
	case '\'':
		open = max(strings.LastIndexByte(body, '\''), strings.LastIndexByte(body, '`'))
	case '"':
		open = strings.LastIndexByte(body, '"')
	default:
		return "", false
	}

	if open < 0 {
		return "", false
	}

	return body[open+1:], true
}

// bubblewrapPlausibleTarget rejects anything that does not look like a path.
// Programs narrate around errno phrases, so without this every "npm ERR! ...
// Permission denied" line would become a violation.
func bubblewrapPlausibleTarget(target string) bool {
	if target == "" || len(target) > bubblewrapMaxTargetLen {
		return false
	}

	if strings.ContainsAny(target, "\x00\n\r") {
		return false
	}

	return strings.Contains(target, "/") || strings.HasPrefix(target, ".")
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
