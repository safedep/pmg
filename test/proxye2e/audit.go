package proxye2e

import (
	"context"
	"sync"

	"github.com/safedep/pmg/internal/audit"
)

// AuditRecorder is an audit sink that keeps every event of a case.
type AuditRecorder struct {
	mu     sync.Mutex
	events []audit.AuditEvent
}

func (r *AuditRecorder) Handle(_ context.Context, event audit.AuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
	return nil
}

func (r *AuditRecorder) Close() error { return nil }

// Events returns the events of one type, in order.
func (r *AuditRecorder) Events(eventType audit.EventType) []audit.AuditEvent {
	r.mu.Lock()
	defer r.mu.Unlock()

	var out []audit.AuditEvent
	for _, e := range r.events {
		if e.Type == eventType {
			out = append(out, e)
		}
	}
	return out
}
