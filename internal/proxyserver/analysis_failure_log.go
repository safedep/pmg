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

// analysisFailureLog writes one line for each package that the daemon allows
// because the analysis failed. The daemon passes stderr, which is the proxy
// log of a detached daemon, because the logger is off without --debug. When
// the analysis service is down, every download fails, so the log writes at
// most analysisFailureMaxLines lines in each analysisFailureWindow and then
// writes how many lines it did not write.
type analysisFailureLog struct {
	out io.Writer
	now func() time.Time

	mu          sync.Mutex
	windowStart time.Time
	written     int
	suppressed  int
}

func newAnalysisFailureLog(out io.Writer) *analysisFailureLog {
	return &analysisFailureLog{out: out, now: time.Now}
}

func (l *analysisFailureLog) Record(pkg *packagev1.PackageVersion, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	if now.Sub(l.windowStart) >= analysisFailureWindow {
		if l.suppressed > 0 {
			l.write(now, fmt.Sprintf("pmg did not write %d more lines about packages allowed without malware analysis", l.suppressed))
		}
		l.windowStart = now
		l.written = 0
		l.suppressed = 0
	}

	if l.written >= analysisFailureMaxLines {
		l.suppressed++
		return
	}
	l.written++

	l.write(now, fmt.Sprintf("Allowed %s without malware analysis: %s",
		ui.PackageVersionPurl(pkg), ui.RemoveControlChars(err.Error())))
}

func (l *analysisFailureLog) write(now time.Time, line string) {
	if _, err := fmt.Fprintf(l.out, "%s %s\n", now.UTC().Format(time.RFC3339), line); err != nil {
		log.Warnf("failed to write the analysis failure line: %v", err)
	}
}
