//go:build linux

package proxyserver

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const runnerWorkerName = "Runner.Worker"

// RunnerExemptGlobs returns the glob for the GitHub Actions runner binaries
// when this process runs inside a job step. The runner must stay exempt, or
// its own traffic to GitHub goes through the proxy. The walk climbs the
// ancestors of this process to Runner.Worker and exempts every binary in
// its directory. It must run in the parent before Daemonize, because the
// daemon starts in a new session with no ancestors left to walk.
func RunnerExemptGlobs() []string {
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		return nil
	}
	exe, ok := findAncestorExecutable(os.Getpid(), runnerWorkerName)
	if !ok {
		return nil
	}
	return []string{runnerGlob(exe)}
}

func runnerGlob(workerExe string) string {
	return filepath.Join(filepath.Dir(workerExe), "Runner.*")
}

// findAncestorExecutable follows parent pids through /proc until it finds a
// process whose executable has the given base name.
func findAncestorExecutable(pid int, base string) (string, bool) {
	for depth := 0; pid > 1 && depth < 64; depth++ {
		exe, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
		if err == nil && filepath.Base(exe) == base {
			return exe, true
		}
		ppid, err := parentPID(pid)
		if err != nil {
			return "", false
		}
		pid = ppid
	}
	return "", false
}

// parentPID reads the fourth field of /proc/<pid>/stat. The second field is
// the command name in parentheses and can hold spaces, so the parse starts
// after the last closing parenthesis.
func parentPID(pid int) (int, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, err
	}
	stat := string(data)
	end := strings.LastIndexByte(stat, ')')
	if end < 0 {
		return 0, os.ErrInvalid
	}
	fields := strings.Fields(stat[end+1:])
	if len(fields) < 2 {
		return 0, os.ErrInvalid
	}
	return strconv.Atoi(fields[1])
}

// processRunning reports whether a process with the given command name
// exists. It reads /proc/<pid>/comm, which needs no extra privilege.
func processRunning(name string) bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		comm, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(comm)) == name {
			return true
		}
	}
	return false
}
