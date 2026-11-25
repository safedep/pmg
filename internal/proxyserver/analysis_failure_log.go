package proxyserver

import (
	"fmt"
	"io"
	"sync"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/internal/ui"
)

const (
	analysisFailureWindow   = time.Minute
	analysisFailureMaxLines = 20
)

// analysisFailureLog writes to the proxy log, because the logger is off
// without --debug. An outage fails every download, so the lines are limited.
type analysisFailureLog struct {
	out io.Writer
	now func() time.Time

	mu          sync.Mutex
	heldBack    string
	windowStart time.Time
	written     int
	suppressed  int
}

func newAnalysisFailureLog(out io.Writer) *analysisFailureLog {
	return &analysisFailureLog{out: out, now: time.Now, heldBack: "allowed"}
}

func (l *analysisFailureLog) Record(pkg *packagev1.PackageVersion, err error, blocked bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	if now.Sub(l.windowStart) >= analysisFailureWindow {
		l.flushLocked(now)
		l.windowStart = now
		l.written = 0
	}

	if l.written >= analysisFailureMaxLines {
		l.suppressed++
		return
	}
	l.written++

	action := "Allowed"
	l.heldBack = "allowed"
	if blocked {
		action = "Blocked"
		l.heldBack = "blocked"
	}
	l.write(now, fmt.Sprintf("%s %s without malware analysis: %s",
		action, ui.PackageVersionPurl(pkg), ui.RemoveControlChars(err.Error())))
}

// Flush writes the count of lines that the limit held back, so the count is
// not lost when no later failure comes.
func (l *analysisFailureLog) Flush() {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.flushLocked(l.now())
}

func (l *analysisFailureLog) flushLocked(now time.Time) {
	if l.suppressed == 0 {
		return
	}
	l.write(now, fmt.Sprintf("pmg did not write %d more lines about packages %s without malware analysis", l.suppressed, l.heldBack))
	l.suppressed = 0
}

func (l *analysisFailureLog) write(now time.Time, line string) {
	if _, err := fmt.Fprintf(l.out, "%s %s\n", now.UTC().Format(time.RFC3339), line); err != nil {
		log.Warnf("failed to write the analysis failure line: %v", err)
	}
}
