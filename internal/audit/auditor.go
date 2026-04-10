package audit

import (
	"context"
	"sync"
	"time"

	"github.com/safedep/dry/log"
)

type session struct {
	mu             sync.Mutex
	startTime      time.Time
	packageManager string
	args           []string
	totalAnalyzed  uint32
	allowedCount   uint32
	blockedCount   uint32
	confirmedCount uint32
	trustedSkipped uint32
}

type auditor struct {
	sinks   []Sink
	session *session
	mu      sync.RWMutex
}

func newAuditor(sinks ...Sink) *auditor {
	return &auditor{sinks: sinks}
}

func (a *auditor) dispatch(ctx context.Context, event AuditEvent) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	for _, s := range a.sinks {
		if err := s.Handle(ctx, event); err != nil {
			log.Warnf("audit sink error: %v", err)
		}
	}
}

func (a *auditor) close() error {
	var firstErr error
	for _, s := range a.sinks {
		if err := s.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (a *auditor) startSession(packageManager string, args []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.session = &session{
		startTime:      time.Now(),
		packageManager: packageManager,
		args:           args,
	}
}

func (a *auditor) getSession() *session {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.session
}

func (a *auditor) recordAllowed() {
	s := a.getSession()
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.allowedCount++
	s.totalAnalyzed++
}

func (a *auditor) recordBlocked() {
	s := a.getSession()
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blockedCount++
	s.totalAnalyzed++
}

func (a *auditor) recordConfirmed() {
	s := a.getSession()
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.confirmedCount++
	s.totalAnalyzed++
}

func (a *auditor) recordTrustedSkipped() {
	s := a.getSession()
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.trustedSkipped++
	s.totalAnalyzed++
}
