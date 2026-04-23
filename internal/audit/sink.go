package audit

import "context"

// Sink processes audit events. Implementations decide which event types they
// care about. Handle must not block the caller for I/O-heavy operations.
type Sink interface {
	Handle(ctx context.Context, event AuditEvent) error
	Close() error
}
