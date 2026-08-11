//go:build linux

package platform

import (
	"strings"
	"testing"

	"github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBubblewrapErrnoSuffix(t *testing.T) {
	tests := []struct {
		name   string
		line   string
		want   string
		wantOK bool
	}{
		{
			name:   "permission denied",
			line:   "cat: /work/.env: Permission denied",
			want:   bubblewrapErrnoEACCES,
			wantOK: true,
		},
		{
			name:   "read only file system",
			line:   "/bin/sh: 1: cannot create /srv/test: Read-only file system",
			want:   bubblewrapErrnoEROFS,
			wantOK: true,
		},
		{
			name:   "operation not permitted",
			line:   "chown: changing ownership of '/x/y': Operation not permitted",
			want:   bubblewrapErrnoEPERM,
			wantOK: true,
		},
		{
			name:   "no such file or directory",
			line:   "bwrap: execvp /usr/bin/git: No such file or directory",
			want:   bubblewrapErrnoENOENT,
			wantOK: true,
		},
		{
			name:   "ordinary package manager noise",
			line:   "npm WARN deprecated left-pad@1.0.0",
			wantOK: false,
		},
		{
			name:   "errno phrase away from the end is not a denial line",
			line:   "PermissionError: [Errno 13] Permission denied: '/work/.env'",
			wantOK: false,
		},
		{
			name:   "empty",
			line:   "",
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := bubblewrapErrnoSuffix(tc.line)
			assert.Equal(t, tc.wantOK, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestBubblewrapViolationKind(t *testing.T) {
	tests := []struct {
		name    string
		message string
		errno   string
		want    sandbox.ViolationKind
	}{
		{
			name:    "bare path defaults to read",
			message: "/work/.env",
			errno:   bubblewrapErrnoEACCES,
			want:    sandbox.ViolationKindFSRead,
		},
		{
			name:    "create is a write",
			message: "cannot create /etc/nope",
			errno:   bubblewrapErrnoEACCES,
			want:    sandbox.ViolationKindFSWrite,
		},
		{
			name:    "longest verb wins over its own prefix",
			message: "cannot remove directory '/opt/pkg'",
			errno:   bubblewrapErrnoEACCES,
			want:    sandbox.ViolationKindFSDeleteOrRename,
		},
		{
			name:    "execvp is an exec",
			message: "execvp /usr/bin/git",
			errno:   bubblewrapErrnoENOENT,
			want:    sandbox.ViolationKindExec,
		},
		{
			name:    "read only filesystem implies a write without a verb",
			message: "/srv/test",
			errno:   bubblewrapErrnoEROFS,
			want:    sandbox.ViolationKindFSWrite,
		},
		{
			name:    "unrecognised verb falls back to read",
			message: "failed while doing something to /work/.env",
			errno:   bubblewrapErrnoEACCES,
			want:    sandbox.ViolationKindFSRead,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, bubblewrapViolationKind(tc.message, tc.errno))
		})
	}
}

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
			name:        "read denied with relative path",
			line:        "cat: work/.env: Permission denied",
			wantOK:      true,
			wantKind:    sandbox.ViolationKindFSRead,
			wantTarget:  "work/.env",
			wantProcess: "cat",
			wantRawKind: bubblewrapErrnoEACCES,
		},
		{
			name:        "program path is not mistaken for the target",
			line:        "/bin/cat: /home/u/.npmrc: Permission denied",
			wantOK:      true,
			wantKind:    sandbox.ViolationKindFSRead,
			wantTarget:  "/home/u/.npmrc",
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
			name:        "gnu style backtick quoting",
			line:        "mkdir: cannot create directory `/opt/pkg': Permission denied",
			wantOK:      true,
			wantKind:    sandbox.ViolationKindFSWrite,
			wantTarget:  "/opt/pkg",
			wantProcess: "mkdir",
			wantRawKind: bubblewrapErrnoEACCES,
		},
		{
			name:        "delete is distinguished from write",
			line:        "rm: cannot remove '/etc/hosts': Permission denied",
			wantOK:      true,
			wantKind:    sandbox.ViolationKindFSDeleteOrRename,
			wantTarget:  "/etc/hosts",
			wantProcess: "rm",
			wantRawKind: bubblewrapErrnoEACCES,
		},
		{
			name:        "unrecognised verb still yields the target",
			line:        "tool: failed while doing something to /work/.env: Permission denied",
			wantOK:      true,
			wantKind:    sandbox.ViolationKindFSRead,
			wantTarget:  "/work/.env",
			wantProcess: "tool",
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
			name:   "errno phrase with no message before it",
			line:   "Permission denied",
			wantOK: false,
		},
		{
			name:   "prose ending in an errno phrase is not a path",
			line:   "npm ERR! the registry returned Permission denied",
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

func TestParseBubblewrapDenialRejectsOversizedTarget(t *testing.T) {
	long := "/" + strings.Repeat("a", bubblewrapMaxTargetLen)
	require.Greater(t, len(long), bubblewrapMaxTargetLen)

	_, ok := parseBubblewrapDenial("cat: " + long + ": Permission denied")
	assert.False(t, ok)
}
