//go:build linux

package platform

import (
	"fmt"
	"strings"
	"testing"

	"github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The lines below were captured from the tools they name, under a real
// bubblewrap sandbox where the scenario allowed it.
func TestParseBubblewrapDenial(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		wantOK      bool
		wantKind    sandbox.ViolationKind
		wantTarget  string
		wantProcess string
		wantRawKind string
	}{
		{
			name:        "read denied on a relative path",
			line:        "cat: work/.env: Permission denied",
			wantOK:      true,
			wantKind:    sandbox.ViolationKindFSRead,
			wantTarget:  "work/.env",
			wantProcess: "cat",
			wantRawKind: bubblewrapErrnoEACCES,
		},
		{
			name:        "absolute program path is not mistaken for the target",
			line:        "/bin/cat: /home/u/.npmrc: Permission denied",
			wantOK:      true,
			wantKind:    sandbox.ViolationKindFSRead,
			wantTarget:  "/home/u/.npmrc",
			wantProcess: "cat",
			wantRawKind: bubblewrapErrnoEACCES,
		},
		{
			name:        "plain project file with no separator or leading dot",
			line:        "cat: package.json: Permission denied",
			wantOK:      true,
			wantKind:    sandbox.ViolationKindFSRead,
			wantTarget:  "package.json",
			wantProcess: "cat",
			wantRawKind: bubblewrapErrnoEACCES,
		},
		{
			name:        "shell write denial carries an extra line number field",
			line:        "sh: 1: cannot create /etc/nope: Permission denied",
			wantOK:      true,
			wantKind:    sandbox.ViolationKindFSWrite,
			wantTarget:  "/etc/nope",
			wantProcess: "sh",
			wantRawKind: bubblewrapErrnoEACCES,
		},
		{
			name:        "write to a read only bind mount",
			line:        "/bin/sh: 1: cannot create /srv/test: Read-only file system",
			wantOK:      true,
			wantKind:    sandbox.ViolationKindFSWrite,
			wantTarget:  "/srv/test",
			wantProcess: "sh",
			wantRawKind: bubblewrapErrnoEROFS,
		},
		{
			name:        "unicode quoting, the coreutils default in a UTF-8 locale",
			line:        "mkdir: cannot create directory ‘/etc/nope’: Permission denied",
			wantOK:      true,
			wantKind:    sandbox.ViolationKindFSWrite,
			wantTarget:  "/etc/nope",
			wantProcess: "mkdir",
			wantRawKind: bubblewrapErrnoEACCES,
		},
		{
			name:        "ascii quoting, the same tool under LC_ALL=C",
			line:        "mkdir: cannot create directory '/etc/nope': Permission denied",
			wantOK:      true,
			wantKind:    sandbox.ViolationKindFSWrite,
			wantTarget:  "/etc/nope",
			wantProcess: "mkdir",
			wantRawKind: bubblewrapErrnoEACCES,
		},
		{
			name:        "older gnu backtick quoting",
			line:        "mkdir: cannot create directory `/opt/pkg': Permission denied",
			wantOK:      true,
			wantKind:    sandbox.ViolationKindFSWrite,
			wantTarget:  "/opt/pkg",
			wantProcess: "mkdir",
			wantRawKind: bubblewrapErrnoEACCES,
		},
		{
			name:        "prose after the path does not displace it",
			line:        "head: cannot open '/etc/shadow' for reading: Permission denied",
			wantOK:      true,
			wantKind:    sandbox.ViolationKindFSRead,
			wantTarget:  "/etc/shadow",
			wantProcess: "head",
			wantRawKind: bubblewrapErrnoEACCES,
		},
		{
			name:        "remove is a delete",
			line:        "rm: cannot remove '/etc/hosts': Permission denied",
			wantOK:      true,
			wantKind:    sandbox.ViolationKindFSDeleteOrRename,
			wantTarget:  "/etc/hosts",
			wantProcess: "rm",
			wantRawKind: bubblewrapErrnoEACCES,
		},
		{
			name:        "rmdir words it as a failure to remove",
			line:        "rmdir: failed to remove '/etc': Permission denied",
			wantOK:      true,
			wantKind:    sandbox.ViolationKindFSDeleteOrRename,
			wantTarget:  "/etc",
			wantProcess: "rmdir",
			wantRawKind: bubblewrapErrnoEACCES,
		},
		{
			name:        "move reports the destination it could not write",
			line:        "mv: cannot move '/etc/hosts' to '/etc/hosts2': Permission denied",
			wantOK:      true,
			wantKind:    sandbox.ViolationKindFSDeleteOrRename,
			wantTarget:  "/etc/hosts2",
			wantProcess: "mv",
			wantRawKind: bubblewrapErrnoEACCES,
		},
		{
			name:        "symlink creation is a write",
			line:        "ln: failed to create symbolic link '/etc/xyz': Permission denied",
			wantOK:      true,
			wantKind:    sandbox.ViolationKindFSWrite,
			wantTarget:  "/etc/xyz",
			wantProcess: "ln",
			wantRawKind: bubblewrapErrnoEACCES,
		},
		{
			name:        "ownership change is a write and reports EPERM",
			line:        "chown: changing ownership of '/etc/shadow': Operation not permitted",
			wantOK:      true,
			wantKind:    sandbox.ViolationKindFSWrite,
			wantTarget:  "/etc/shadow",
			wantProcess: "chown",
			wantRawKind: bubblewrapErrnoEPERM,
		},
		{
			name:        "colon in the path survives colon-space splitting",
			line:        "cat: 'work/a:b.txt': Permission denied",
			wantOK:      true,
			wantKind:    sandbox.ViolationKindFSRead,
			wantTarget:  "work/a:b.txt",
			wantProcess: "cat",
			wantRawKind: bubblewrapErrnoEACCES,
		},
		{
			name:        "quoting recovers a path containing spaces",
			line:        "cat: '/work/my notes.txt': Permission denied",
			wantOK:      true,
			wantKind:    sandbox.ViolationKindFSRead,
			wantTarget:  "/work/my notes.txt",
			wantProcess: "cat",
			wantRawKind: bubblewrapErrnoEACCES,
		},
		{
			name:        "an extra context field does not shift the target",
			line:        "sort: cannot read: /etc/shadow: Permission denied",
			wantOK:      true,
			wantKind:    sandbox.ViolationKindFSRead,
			wantTarget:  "/etc/shadow",
			wantProcess: "sort",
			wantRawKind: bubblewrapErrnoEACCES,
		},
		{
			name:        "unlisted verb still yields the target",
			line:        "ugrep: warning: cannot read /etc/shadow: Permission denied",
			wantOK:      true,
			wantKind:    sandbox.ViolationKindFSRead,
			wantTarget:  "/etc/shadow",
			wantProcess: "ugrep",
			wantRawKind: bubblewrapErrnoEACCES,
		},
		{
			name:        "bwrap reported exec failure is a trustworthy ENOENT",
			line:        "bwrap: execvp /usr/bin/git: No such file or directory",
			wantOK:      true,
			wantKind:    sandbox.ViolationKindExec,
			wantTarget:  "/usr/bin/git",
			wantProcess: "bwrap",
			wantRawKind: bubblewrapErrnoENOENT,
		},
		{
			name:   "program reported ENOENT is ambiguous and skipped",
			line:   "/bin/cat: /home/u/.ssh/id_rsa: No such file or directory",
			wantOK: false,
		},
		{
			name:   "bwrap setup failure is not a runtime denial",
			line:   "bwrap: Can't find source path /nonexistent: No such file or directory",
			wantOK: false,
		},
		{
			name:   "python inverts path and errno so it is not parsed",
			line:   "PermissionError: [Errno 13] Permission denied: '/work/.env'",
			wantOK: false,
		},
		{
			name:   "ordinary package manager noise",
			line:   "npm WARN deprecated left-pad@1.0.0",
			wantOK: false,
		},
		{
			name:   "prose ending in an errno phrase is not a path",
			line:   "npm ERR! the registry returned Permission denied",
			wantOK: false,
		},
		{
			name:   "elision in narration is not a path",
			line:   "npm ERR! ... Permission denied",
			wantOK: false,
		},
		{
			name:   "bare word after a colon is not a path",
			line:   "npm ERR! syscall: open Permission denied",
			wantOK: false,
		},
		{
			name:   "errno phrase with no message before it",
			line:   "Permission denied",
			wantOK: false,
		},
		{
			name:   "blank line",
			line:   "   ",
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseBubblewrapDenial(tc.line)

			if !tc.wantOK {
				assert.False(t, ok)
				return
			}

			require.True(t, ok)
			assert.Equal(t, tc.wantKind, got.kind)
			assert.Equal(t, tc.wantTarget, got.target)
			assert.Equal(t, tc.wantProcess, got.process)
			assert.Equal(t, tc.wantRawKind, got.rawKind)
			assert.Equal(t, strings.TrimSpace(tc.line), got.raw)
		})
	}
}

func TestParseBubblewrapDenialKeepsRawLineAsPrinted(t *testing.T) {
	line := "bfs: error: /root: Permission denied."

	got, ok := parseBubblewrapDenial(line)
	require.True(t, ok)

	assert.Equal(t, "/root", got.target)
	assert.Equal(t, line, got.raw)
}

func TestParseBubblewrapDenialRejectsOversizedTarget(t *testing.T) {
	long := "/" + strings.Repeat("a", bubblewrapMaxTargetLen)
	require.Greater(t, len(long), bubblewrapMaxTargetLen)

	_, ok := parseBubblewrapDenial("cat: " + long + ": Permission denied")
	assert.False(t, ok)
}

func TestBubblewrapStderrTapReassemblesLinesAcrossWrites(t *testing.T) {
	tap := newBubblewrapStderrTap()

	chunks := []string{"npm WARN x\nca", "t: /work", "/.env: Permis", "sion denied\nnpm ERR! code 1\n"}
	for _, chunk := range chunks {
		n, err := tap.Write([]byte(chunk))
		require.NoError(t, err)
		assert.Equal(t, len(chunk), n)
	}

	denials := tap.collect()
	require.Len(t, denials, 1)
	assert.Equal(t, "/work/.env", denials[0].target)
	assert.Equal(t, sandbox.ViolationKindFSRead, denials[0].kind)
}

func TestBubblewrapStderrTapFlushesUnterminatedLine(t *testing.T) {
	tap := newBubblewrapStderrTap()

	_, err := tap.Write([]byte("cat: /work/.npmrc: Permission denied"))
	require.NoError(t, err)

	denials := tap.collect()
	require.Len(t, denials, 1)
	assert.Equal(t, "/work/.npmrc", denials[0].target)
}

// A retry loop on one denied path must not fill the buffer and evict a later
// distinct denial, so dedupe happens before the cap applies.
func TestBubblewrapStderrTapDedupesBeforeCapping(t *testing.T) {
	tap := newBubblewrapStderrTap()

	for range bubblewrapDenialCap * 2 {
		_, err := tap.Write([]byte("cat: /work/.env: Permission denied\n"))
		require.NoError(t, err)
	}

	_, err := tap.Write([]byte("cat: /work/.npmrc: Permission denied\n"))
	require.NoError(t, err)

	denials := tap.collect()
	require.Len(t, denials, 2)
	assert.Equal(t, "/work/.env", denials[0].target)
	assert.Equal(t, "/work/.npmrc", denials[1].target)
}

func TestBubblewrapStderrTapBoundsDistinctDenials(t *testing.T) {
	tap := newBubblewrapStderrTap()

	for i := range bubblewrapDenialCap + 100 {
		_, err := fmt.Fprintf(tap, "cat: /work/%d.env: Permission denied\n", i)
		require.NoError(t, err)
	}

	assert.Len(t, tap.collect(), bubblewrapDenialCap)
	assert.Len(t, tap.seen, bubblewrapDenialCap)
}

func TestBubblewrapStderrTapAbandonsOversizedLine(t *testing.T) {
	tap := newBubblewrapStderrTap()

	flood := strings.Repeat("x", bubblewrapMaxLineLen+1)
	_, err := tap.Write([]byte(flood + "/work/.env: Permission denied\n"))
	require.NoError(t, err)
	assert.Empty(t, tap.collect())

	_, err = tap.Write([]byte("cat: /work/.env: Permission denied\n"))
	require.NoError(t, err)
	assert.Len(t, tap.collect(), 1)
}
