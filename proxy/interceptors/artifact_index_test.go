package interceptors

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/safedep/pmg/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestArtifactIndexResolvesAndNormalizesURLs(t *testing.T) {
	clock := newArtifactIndexTestClock()
	index := newArtifactIndexWithOptions(10, time.Minute, clock.Now)
	base := mustParseArtifactURL(t, "https://Registry.Example:443/npm/pkg?metadata=1")

	tests := []struct {
		name    string
		ref     string
		lookup  string
		present bool
	}{
		{name: "relative", ref: "../files/pkg.tgz", lookup: "https://registry.example/files/pkg.tgz", present: true},
		{name: "absolute origin normalization", ref: "HTTPS://REGISTRY.EXAMPLE:443/files/other.tgz", lookup: "https://registry.example/files/other.tgz", present: true},
		{name: "fragment removed", ref: "../files/fragment.tgz#sha256=abc", lookup: "https://registry.example/files/fragment.tgz", present: true},
		{name: "escaped slash preserved and escape case normalized", ref: "../files/a%2fb.tgz", lookup: "https://registry.example/files/a%2Fb.tgz", present: true},
		{name: "escaped slash is not decoded", ref: "../files/encoded%2Fslash.tgz", lookup: "https://registry.example/files/encoded/slash.tgz", present: false},
		{name: "query preserved", ref: "../files/signed.tgz?token=A%2fb&part=1", lookup: "https://registry.example/files/signed.tgz?token=A%2fb&part=1", present: true},
		{name: "query difference", ref: "../files/query.tgz?token=one", lookup: "https://registry.example/files/query.tgz?token=two", present: false},
		{name: "nondefault port preserved", ref: "https://registry.example:8443/files/port.tgz", lookup: "https://REGISTRY.EXAMPLE:8443/files/port.tgz", present: true},
		{name: "IPv6 default port normalized", ref: "https://[2001:db8::1]:443/files/ipv6.tgz", lookup: "https://[2001:DB8::1]/files/ipv6.tgz", present: true},
	}

	for indexNumber, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			identity := artifactIdentity{Name: fmt.Sprintf("pkg-%d", indexNumber), Version: "1.0.0"}
			require.NoError(t, index.Add("npm", base, test.ref, identity))

			actual, ok := index.Get("npm", mustParseArtifactURL(t, test.lookup))
			assert.Equal(t, test.present, ok)
			if test.present {
				assert.Equal(t, identity, actual)
			}
		})
	}
}

func TestArtifactIndexKeepsRegistriesIsolated(t *testing.T) {
	index := newArtifactIndexWithOptions(10, time.Minute, time.Now)
	base := mustParseArtifactURL(t, "https://registry.example/npm/pkg")
	artifact := mustParseArtifactURL(t, "https://cdn.example/pkg.tgz")
	identity := artifactIdentity{Name: "pkg", Version: "1.0.0"}

	require.NoError(t, index.Add("registry-a", base, artifact.String(), identity))

	actual, ok := index.Get("registry-a", artifact)
	assert.True(t, ok)
	assert.Equal(t, identity, actual)
	_, ok = index.Get("registry-b", artifact)
	assert.False(t, ok)
}

func TestArtifactIndexExpiresEntries(t *testing.T) {
	clock := newArtifactIndexTestClock()
	index := newArtifactIndexWithOptions(10, 15*time.Minute, clock.Now)
	base := mustParseArtifactURL(t, "https://registry.example/pkg")
	artifact := mustParseArtifactURL(t, "https://registry.example/pkg.tgz")

	require.NoError(t, index.Add("npm", base, artifact.String(), artifactIdentity{Name: "pkg", Version: "1"}))
	clock.Advance(15*time.Minute - time.Nanosecond)
	_, ok := index.Get("npm", artifact)
	assert.True(t, ok)
	clock.Advance(time.Nanosecond)
	_, ok = index.Get("npm", artifact)
	assert.False(t, ok)
}

func TestArtifactIndexPrunesExpiredBeforeEvictingLiveEntries(t *testing.T) {
	clock := newArtifactIndexTestClock()
	index := newArtifactIndexWithOptions(2, time.Minute, clock.Now)
	base := mustParseArtifactURL(t, "https://registry.example/metadata")
	first := mustParseArtifactURL(t, "https://registry.example/first.tgz")
	second := mustParseArtifactURL(t, "https://registry.example/second.tgz")
	third := mustParseArtifactURL(t, "https://registry.example/third.tgz")

	require.NoError(t, index.Add("npm", base, first.String(), artifactIdentity{Name: "first", Version: "1"}))
	clock.Advance(30 * time.Second)
	require.NoError(t, index.Add("npm", base, second.String(), artifactIdentity{Name: "second", Version: "1"}))
	clock.Advance(31 * time.Second)
	require.NoError(t, index.Add("npm", base, third.String(), artifactIdentity{Name: "third", Version: "1"}))

	_, ok := index.Get("npm", first)
	assert.False(t, ok)
	_, ok = index.Get("npm", second)
	assert.True(t, ok)
	_, ok = index.Get("npm", third)
	assert.True(t, ok)
}

func TestArtifactIndexEvictsOldestWithStableTieBreaking(t *testing.T) {
	clock := newArtifactIndexTestClock()
	index := newArtifactIndexWithOptions(2, time.Hour, clock.Now)
	base := mustParseArtifactURL(t, "https://registry.example/metadata")
	first := mustParseArtifactURL(t, "https://registry.example/first.tgz")
	second := mustParseArtifactURL(t, "https://registry.example/second.tgz")
	third := mustParseArtifactURL(t, "https://registry.example/third.tgz")

	require.NoError(t, index.Add("npm", base, first.String(), artifactIdentity{Name: "first", Version: "1"}))
	require.NoError(t, index.Add("npm", base, second.String(), artifactIdentity{Name: "second", Version: "1"}))
	require.NoError(t, index.Add("npm", base, third.String(), artifactIdentity{Name: "third", Version: "1"}))

	_, ok := index.Get("npm", first)
	assert.False(t, ok)
	_, ok = index.Get("npm", second)
	assert.True(t, ok)
	_, ok = index.Get("npm", third)
	assert.True(t, ok)
}

func TestArtifactIndexDuplicateUpdateRefreshesValueAndAge(t *testing.T) {
	clock := newArtifactIndexTestClock()
	index := newArtifactIndexWithOptions(2, time.Hour, clock.Now)
	base := mustParseArtifactURL(t, "https://registry.example/metadata")
	first := mustParseArtifactURL(t, "https://registry.example/first.tgz")
	second := mustParseArtifactURL(t, "https://registry.example/second.tgz")
	third := mustParseArtifactURL(t, "https://registry.example/third.tgz")

	require.NoError(t, index.Add("npm", base, first.String(), artifactIdentity{Name: "first", Version: "1"}))
	require.NoError(t, index.Add("npm", base, second.String(), artifactIdentity{Name: "second", Version: "1"}))
	require.NoError(t, index.Add("npm", base, first.String(), artifactIdentity{Name: "first", Version: "2"}))
	require.NoError(t, index.Add("npm", base, third.String(), artifactIdentity{Name: "third", Version: "1"}))

	actual, ok := index.Get("npm", first)
	assert.True(t, ok)
	assert.Equal(t, artifactIdentity{Name: "first", Version: "2"}, actual)
	_, ok = index.Get("npm", second)
	assert.False(t, ok)
}

func TestArtifactIndexRejectsInvalidInputs(t *testing.T) {
	index := newArtifactIndexWithOptions(10, time.Minute, time.Now)
	validBase := mustParseArtifactURL(t, "https://registry.example/pkg")
	identity := artifactIdentity{Name: "pkg", Version: "1"}

	tests := []struct {
		name     string
		registry string
		base     *url.URL
		ref      string
		identity artifactIdentity
	}{
		{name: "empty registry", base: validBase, ref: "pkg.tgz", identity: identity},
		{name: "nil base", registry: "npm", ref: "pkg.tgz", identity: identity},
		{name: "relative base", registry: "npm", base: mustParseArtifactURL(t, "/pkg"), ref: "pkg.tgz", identity: identity},
		{name: "unsupported base scheme", registry: "npm", base: mustParseArtifactURL(t, "file:///pkg"), ref: "pkg.tgz", identity: identity},
		{name: "base credentials", registry: "npm", base: mustParseArtifactURL(t, "https://user:secret@registry.example/pkg"), ref: "pkg.tgz", identity: identity},
		{name: "invalid base port", registry: "npm", base: &url.URL{Scheme: "https", Host: "registry.example:invalid", Path: "/pkg"}, ref: "pkg.tgz", identity: identity},
		{name: "empty ref", registry: "npm", base: validBase, identity: identity},
		{name: "malformed ref", registry: "npm", base: validBase, ref: "%zz", identity: identity},
		{name: "unsupported resolved scheme", registry: "npm", base: validBase, ref: "file:///pkg.tgz", identity: identity},
		{name: "resolved credentials", registry: "npm", base: validBase, ref: "https://user:secret@registry.example/pkg.tgz", identity: identity},
		{name: "empty package name", registry: "npm", base: validBase, ref: "pkg.tgz", identity: artifactIdentity{Version: "1"}},
		{name: "empty version", registry: "npm", base: validBase, ref: "pkg.tgz", identity: artifactIdentity{Name: "pkg"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Error(t, index.Add(test.registry, test.base, test.ref, test.identity))
		})
	}

	_, ok := index.Get("npm", nil)
	assert.False(t, ok)
	_, ok = index.Get("", validBase)
	assert.False(t, ok)
}

func TestArtifactIndexErrorsDoNotExposeURLSecrets(t *testing.T) {
	index := newArtifactIndexWithOptions(10, time.Minute, time.Now)
	identity := artifactIdentity{Name: "pkg", Version: "1"}
	validBase := mustParseArtifactURL(t, "https://registry.example/metadata")

	tests := []struct {
		name    string
		base    *url.URL
		ref     string
		secrets []string
	}{
		{
			name: "credential-bearing base",
			base: mustParseArtifactURL(t, "https://base-user:base-password@registry.example/metadata?token=base-secret"),
			ref:  "artifact.tgz",
			secrets: []string{
				"base-user",
				"base-password",
				"base-secret",
				"registry.example",
			},
		},
		{
			name: "malformed reference",
			base: validBase,
			ref:  "%zz?token=reference-secret",
			secrets: []string{
				"%zz",
				"reference-secret",
				"registry.example",
			},
		},
		{
			name: "credential-bearing reference",
			base: validBase,
			ref:  "https://ref-user:ref-password@artifacts.example/pkg.tgz?token=artifact-secret",
			secrets: []string{
				"ref-user",
				"ref-password",
				"artifact-secret",
				"artifacts.example",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := index.Add("npm", test.base, test.ref, identity)
			require.Error(t, err)
			for _, secret := range test.secrets {
				assert.NotContains(t, err.Error(), secret)
			}
		})
	}
}

func TestArtifactIndexConcurrentAccess(t *testing.T) {
	index := newArtifactIndexWithOptions(100, time.Minute, time.Now)
	base := mustParseArtifactURL(t, "https://registry.example/metadata")
	var workers sync.WaitGroup
	errs := make(chan error, 2_000)

	for worker := 0; worker < 20; worker++ {
		worker := worker
		workers.Add(1)
		go func() {
			defer workers.Done()
			for iteration := 0; iteration < 100; iteration++ {
				ref := fmt.Sprintf("../files/%d-%d.tgz?token=%d", worker, iteration%10, iteration)
				identity := artifactIdentity{Name: fmt.Sprintf("pkg-%d", worker), Version: fmt.Sprint(iteration)}
				if err := index.Add("npm", base, ref, identity); err != nil {
					errs <- err
				}
				resolved, err := base.Parse(ref)
				if err != nil {
					errs <- err
					continue
				}
				index.Get("npm", resolved)
			}
		}()
	}

	workers.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
}

func TestNewArtifactIndexUsesProductionDefaults(t *testing.T) {
	index := newArtifactIndex()

	assert.Equal(t, 10_000, index.limit)
	assert.Equal(t, 15*time.Minute, index.ttl)
	require.NotNil(t, index.now)
}

func TestChainResponseModifiersRunsInOrder(t *testing.T) {
	var calls []string
	first := func(status int, headers http.Header, body []byte) (int, http.Header, []byte, error) {
		calls = append(calls, "first")
		assert.Equal(t, 200, status)
		assert.Equal(t, []byte("upstream"), body)
		headers.Set("X-First", "set")
		return 201, headers, append(body, []byte("-first")...), nil
	}
	second := func(status int, headers http.Header, body []byte) (int, http.Header, []byte, error) {
		calls = append(calls, "second")
		assert.Equal(t, 201, status)
		assert.Equal(t, "set", headers.Get("X-First"))
		assert.Equal(t, []byte("upstream-first"), body)
		return 202, headers, append(body, []byte("-second")...), nil
	}

	modifier := chainResponseModifiers(first, second)
	status, headers, body, err := modifier(200, http.Header{}, []byte("upstream"))

	require.NoError(t, err)
	assert.Equal(t, []string{"first", "second"}, calls)
	assert.Equal(t, 202, status)
	assert.Equal(t, "set", headers.Get("X-First"))
	assert.Equal(t, []byte("upstream-first-second"), body)
}

func TestChainResponseModifiersStopsOnError(t *testing.T) {
	expectedErr := errors.New("modifier failed")
	called := false
	first := func(status int, headers http.Header, body []byte) (int, http.Header, []byte, error) {
		return 201, headers, []byte("first"), expectedErr
	}
	second := func(status int, headers http.Header, body []byte) (int, http.Header, []byte, error) {
		called = true
		return status, headers, body, nil
	}

	status, _, body, err := chainResponseModifiers(first, nil, second)(200, http.Header{}, []byte("upstream"))

	assert.ErrorIs(t, err, expectedErr)
	assert.Equal(t, 201, status)
	assert.Equal(t, []byte("first"), body)
	assert.False(t, called)
}

type artifactIndexTestClock struct {
	mu  sync.Mutex
	now time.Time
}

func newArtifactIndexTestClock() *artifactIndexTestClock {
	return &artifactIndexTestClock{now: time.Date(2026, time.August, 18, 0, 0, 0, 0, time.UTC)}
}

func (c *artifactIndexTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *artifactIndexTestClock) Advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(duration)
}

func mustParseArtifactURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	require.NoError(t, err)
	return parsed
}

var _ proxy.ResponseModifierFunc = chainResponseModifiers()
