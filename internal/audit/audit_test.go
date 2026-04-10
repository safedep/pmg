package audit

import (
	"context"
	"sync"
	"testing"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockSink struct {
	mu     sync.Mutex
	events []AuditEvent
	closed bool
}

func (m *mockSink) Handle(_ context.Context, event AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
	return nil
}

func (m *mockSink) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *mockSink) getEvents() []AuditEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]AuditEvent, len(m.events))
	copy(cp, m.events)
	return cp
}

func testPackageVersion(name, version, ecosystem string) *packagev1.PackageVersion {
	eco := packagev1.Ecosystem_ECOSYSTEM_UNSPECIFIED
	switch ecosystem {
	case "npm":
		eco = packagev1.Ecosystem_ECOSYSTEM_NPM
	case "pypi":
		eco = packagev1.Ecosystem_ECOSYSTEM_PYPI
	}
	return &packagev1.PackageVersion{
		Package: &packagev1.Package{
			Name:      name,
			Ecosystem: eco,
		},
		Version: version,
	}
}

func TestAuditorDispatchesToAllSinks(t *testing.T) {
	s1 := &mockSink{}
	s2 := &mockSink{}
	a := newAuditor(s1, s2)

	event := AuditEvent{Type: EventTypeMalwareBlocked, Message: "test"}
	a.dispatch(context.Background(), event)

	assert.Len(t, s1.getEvents(), 1)
	assert.Len(t, s2.getEvents(), 1)
	assert.Equal(t, EventTypeMalwareBlocked, s1.getEvents()[0].Type)
	assert.Equal(t, EventTypeMalwareBlocked, s2.getEvents()[0].Type)
}

func TestAuditorSetsTimestamp(t *testing.T) {
	s := &mockSink{}
	a := newAuditor(s)

	before := time.Now()
	a.dispatch(context.Background(), AuditEvent{Type: EventTypeError})
	after := time.Now()

	events := s.getEvents()
	require.Len(t, events, 1)
	assert.False(t, events[0].Timestamp.IsZero())
	assert.True(t, !events[0].Timestamp.Before(before))
	assert.True(t, !events[0].Timestamp.After(after))
}

func TestAuditorCloseClosesAllSinks(t *testing.T) {
	s1 := &mockSink{}
	s2 := &mockSink{}
	a := newAuditor(s1, s2)

	err := a.close()
	require.NoError(t, err)
	assert.True(t, s1.closed)
	assert.True(t, s2.closed)
}

func TestAuditorSessionTracking(t *testing.T) {
	a := newAuditor()

	// No session yet — record calls are no-ops
	a.recordAllowed()
	assert.Nil(t, a.getSession())

	a.startSession("npm", []string{"install", "lodash"})
	s := a.getSession()
	require.NotNil(t, s)
	assert.Equal(t, "npm", s.packageManager)
	assert.Equal(t, []string{"install", "lodash"}, s.args)

	a.recordAllowed()
	a.recordBlocked()
	a.recordConfirmed()
	a.recordTrustedSkipped()

	s.mu.Lock()
	defer s.mu.Unlock()
	assert.Equal(t, uint32(4), s.totalAnalyzed)
	assert.Equal(t, uint32(1), s.allowedCount)
	assert.Equal(t, uint32(1), s.blockedCount)
	assert.Equal(t, uint32(1), s.confirmedCount)
	assert.Equal(t, uint32(1), s.trustedSkipped)
}

func TestPublicAPIDispatchesToSinks(t *testing.T) {
	s := &mockSink{}
	a := newAuditor(s)
	setGlobal(a)
	defer resetGlobal()

	pv := testPackageVersion("evil", "1.0.0", "npm")
	LogMalwareBlocked(pv, "malware", "analysis-1", "https://ref", true, false)

	events := s.getEvents()
	require.Len(t, events, 1)
	assert.Equal(t, EventTypeMalwareBlocked, events[0].Type)
	assert.Equal(t, pv, events[0].PackageVersion)
	assert.Equal(t, "malware", events[0].Details["reason"])
	assert.Equal(t, "analysis-1", events[0].AnalysisID)
	assert.Equal(t, true, events[0].IsMalware)
}

func TestPublicAPISilentWhenNotInitialized(t *testing.T) {
	resetGlobal()

	// None of these should panic
	LogMalwareBlocked(nil, "reason", "", "", false, false)
	LogMalwareConfirmed(nil)
	LogInstallAllowed(nil, 5)
	LogInstallTrustedAllowed(nil)
	LogInstallInsecureBypass(nil)
	LogInstallStarted("npm", []string{"install"})
	LogProxyHostObserved("host", "GET", "reason", nil)
	LogSandboxOverride("profile", nil)
	LogError("err", nil)
}

func TestLogInstallStartedInitializesSession(t *testing.T) {
	s := &mockSink{}
	a := newAuditor(s)
	setGlobal(a)
	defer resetGlobal()

	LogInstallStarted("pip", []string{"install", "requests"})

	sess := a.getSession()
	require.NotNil(t, sess)
	assert.Equal(t, "pip", sess.packageManager)
	assert.Equal(t, []string{"install", "requests"}, sess.args)
}

func TestLogInstallAllowedIncrementsSession(t *testing.T) {
	s := &mockSink{}
	a := newAuditor(s)
	setGlobal(a)
	defer resetGlobal()

	a.startSession("npm", nil)
	LogInstallAllowed(testPackageVersion("pkg", "1.0", "npm"), 3)

	sess := a.getSession()
	require.NotNil(t, sess)
	assert.Equal(t, uint32(1), sess.allowedCount)
	assert.Equal(t, uint32(1), sess.totalAnalyzed)
}

func TestLogMalwareBlockedIncrementsSession(t *testing.T) {
	s := &mockSink{}
	a := newAuditor(s)
	setGlobal(a)
	defer resetGlobal()

	a.startSession("npm", nil)
	LogMalwareBlocked(testPackageVersion("evil", "1.0", "npm"), "bad", "", "", true, false)

	sess := a.getSession()
	require.NotNil(t, sess)
	assert.Equal(t, uint32(1), sess.blockedCount)
	assert.Equal(t, uint32(1), sess.totalAnalyzed)
}

func TestLogMalwareConfirmedIncrementsSession(t *testing.T) {
	s := &mockSink{}
	a := newAuditor(s)
	setGlobal(a)
	defer resetGlobal()

	a.startSession("npm", nil)
	LogMalwareConfirmed(testPackageVersion("pkg", "1.0", "npm"))

	sess := a.getSession()
	require.NotNil(t, sess)
	assert.Equal(t, uint32(1), sess.confirmedCount)
	assert.Equal(t, uint32(1), sess.totalAnalyzed)
}

func TestLogInstallTrustedAllowedIncrementsSession(t *testing.T) {
	s := &mockSink{}
	a := newAuditor(s)
	setGlobal(a)
	defer resetGlobal()

	a.startSession("npm", nil)
	LogInstallTrustedAllowed(testPackageVersion("pkg", "1.0", "npm"))

	sess := a.getSession()
	require.NotNil(t, sess)
	assert.Equal(t, uint32(1), sess.trustedSkipped)
	assert.Equal(t, uint32(1), sess.totalAnalyzed)
}
