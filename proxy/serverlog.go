package proxy

import (
	stdlog "log"
	"strings"
	"sync"
	"time"

	"github.com/safedep/dry/log"
)

// serverLog receives http.Server's own log lines. A TLS handshake that the
// client aborted because it does not trust the proxy certificate is the one
// failure the operator must hear about, because a redirected client fails
// that way when the CA never reached it. The line goes to onRejected, at
// most once per hintInterval. Everything else stays at debug, where the
// probe noise of a listener belongs.
type serverLog struct {
	onRejected func(line string)
	mu         sync.Mutex
	lastHint   time.Time
}

const hintInterval = time.Minute

func newServerLog(onRejected func(line string)) *stdlog.Logger {
	return stdlog.New(&serverLog{onRejected: onRejected}, "", 0)
}

func (l *serverLog) Write(p []byte) (int, error) {
	line := strings.TrimSpace(string(p))
	switch {
	case !clientRejectedCertificate(line) || !l.takeHint():
		log.Debugf("%s", line)
	case l.onRejected == nil:
		log.Warnf("%s: the client does not trust the proxy certificate", line)
	default:
		l.onRejected(line)
	}
	return len(p), nil
}

// takeHint reports whether a hint may fire now, and starts the interval.
func (l *serverLog) takeHint() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if time.Since(l.lastHint) < hintInterval {
		return false
	}
	l.lastHint = time.Now()
	return true
}

// clientRejectedCertificate matches the alerts a TLS client sends when it
// cannot build a chain to the proxy's certificate. curl's alert arrives
// under keys the server does not have yet and surfaces as a bad record
// MAC, so that line counts too.
func clientRejectedCertificate(line string) bool {
	for _, alert := range []string{"unknown certificate authority", "bad certificate", "certificate unknown", "bad record MAC"} {
		if strings.Contains(line, alert) {
			return true
		}
	}
	return false
}
