// Package cloudauthtest runs a stub of the SafeDep Cloud
// WorkloadIdentityService and of the GitHub Actions ID token endpoint for
// tests. A test runs the real exchange client of pmg against it.
package cloudauthtest

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/controltower/v1/controltowerv1grpc"
	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
	"github.com/safedep/dry/cloud"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	_ "google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// IDToken is the ID token that the stub GitHub endpoint issues.
	IDToken = "github-id-token"
	// AccessToken is the access token of the credential that the stub issues.
	AccessToken = "workload-access-token"
	// EndpointID is the endpoint id that the stub sets from the claims.
	EndpointID = "gh:acme/app"
	// CredentialID is the id of the credential that the stub issues.
	CredentialID = "wic_stub"

	requestToken = "request-token"
)

// Exchange is a stub WorkloadIdentityService. The ExchangeToken calls take
// the errors of FirstErrs in order. Then Err, when set, is the answer to
// every call. The RevokeToken calls take RevokeFirstErrs and RevokeErr in
// the same way. With Hang, every call waits until the client gives up. With
// HangFirst, the first HangFirst ExchangeToken calls wait until the client
// gives up. HangFirstRevoke does the same for the RevokeToken calls.
type Exchange struct {
	controltowerv1grpc.UnimplementedWorkloadIdentityServiceServer

	FirstErrs       []error
	Err             error
	RevokeFirstErrs []error
	RevokeErr       error
	Hang            bool
	HangFirst       int
	HangFirstRevoke int

	mu        sync.Mutex
	hung      int
	exchanges []*controltowerv1.ExchangeTokenRequest
	revokes   []*controltowerv1.RevokeTokenRequest
	auth      []string
	toolAuth  []string
}

// Exchanges returns the ExchangeToken requests.
func (s *Exchange) Exchanges() []*controltowerv1.ExchangeTokenRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*controltowerv1.ExchangeTokenRequest(nil), s.exchanges...)
}

// Revokes returns the RevokeToken requests, also the requests that hang.
func (s *Exchange) Revokes() []*controltowerv1.RevokeTokenRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*controltowerv1.RevokeTokenRequest(nil), s.revokes...)
}

// Authorization returns the authorization headers of the calls. The
// WorkloadIdentityService is keyless, so a client must send none.
func (s *Exchange) Authorization() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.auth...)
}

// ToolAuthorization returns the authorization headers of the calls to the
// other data plane services, which the stub does not implement. A tool that
// holds the workload credential sends its access token there.
func (s *Exchange) ToolAuthorization() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.toolAuth...)
}

func (s *Exchange) unknownService(_ any, stream grpc.ServerStream) error {
	md, _ := metadata.FromIncomingContext(stream.Context())
	s.mu.Lock()
	s.toolAuth = append(s.toolAuth, md.Get("authorization")...)
	s.mu.Unlock()
	return status.Error(codes.Unimplemented, "the stub serves only the WorkloadIdentityService")
}

func (s *Exchange) recordAuth(ctx context.Context) {
	md, _ := metadata.FromIncomingContext(ctx)
	s.auth = append(s.auth, md.Get("authorization")...)
}

func (s *Exchange) ExchangeToken(ctx context.Context, req *controltowerv1.ExchangeTokenRequest) (*controltowerv1.ExchangeTokenResponse, error) {
	s.mu.Lock()
	hang := s.Hang || s.hung < s.HangFirst
	if hang {
		s.hung++
	}
	s.mu.Unlock()
	if hang {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.exchanges = append(s.exchanges, req)
	s.recordAuth(ctx)
	if n := len(s.exchanges); n <= len(s.FirstErrs) && s.FirstErrs[n-1] != nil {
		return nil, s.FirstErrs[n-1]
	}
	if s.Err != nil {
		return nil, s.Err
	}

	res := &controltowerv1.ExchangeTokenResponse{}
	res.SetAccessToken(AccessToken)
	res.SetExpiresAt(timestamppb.New(time.Now().Add(6 * time.Hour)))
	res.SetTenantDomain(req.GetTenantDomain())
	res.SetEndpointId(EndpointID)
	res.SetCredentialId(CredentialID)
	return res, nil
}

func (s *Exchange) RevokeToken(ctx context.Context, req *controltowerv1.RevokeTokenRequest) (*controltowerv1.RevokeTokenResponse, error) {
	s.mu.Lock()
	s.revokes = append(s.revokes, req)
	s.recordAuth(ctx)
	n := len(s.revokes)
	s.mu.Unlock()
	if s.Hang || n <= s.HangFirstRevoke {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if n <= len(s.RevokeFirstErrs) && s.RevokeFirstErrs[n-1] != nil {
		return nil, s.RevokeFirstErrs[n-1]
	}
	if s.RevokeErr != nil {
		return nil, s.RevokeErr
	}
	return &controltowerv1.RevokeTokenResponse{}, nil
}

// Start serves stub on the loopback address until the test ends. It returns
// the environment that points the exchange client at the stub and gives a
// GitHub Actions workload identity.
func Start(t *testing.T, stub *Exchange) map[string]string {
	t.Helper()
	return StartOn(t, stub, "127.0.0.1")
}

// StartOn serves stub on host. Go clients never send a call to a loopback
// address through HTTPS_PROXY, so a test of the proxy variables needs
// another address.
func StartOn(t *testing.T, stub *Exchange, host string) map[string]string {
	t.Helper()

	lis, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	require.NoError(t, err)
	srv := grpc.NewServer(grpc.UnknownServiceHandler(stub.unknownService))
	controltowerv1grpc.RegisterWorkloadIdentityServiceServer(srv, stub)
	served := make(chan error, 1)
	go func() { served <- srv.Serve(lis) }()
	t.Cleanup(func() {
		srv.Stop()
		// Serve returns nil after Stop, or ErrServerStopped when Stop came
		// first. Any other error means that the stub died during the test,
		// and the client saw a timeout instead.
		if err := <-served; !errors.Is(err, grpc.ErrServerStopped) {
			assert.NoError(t, err, "the stub WorkloadIdentityService stopped")
		}
	})

	idToken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer "+requestToken, r.Header.Get("Authorization"))
		assert.Equal(t, cloud.WorkloadIdentityAudience, r.URL.Query().Get("audience"))
		assert.NoError(t, json.NewEncoder(w).Encode(map[string]string{"value": IDToken}))
	}))
	t.Cleanup(idToken.Close)

	return map[string]string{
		"INSECURE_GRPC_CLIENT_USE_INSECURE_TRANSPORT": "true",
		"SAFEDEP_CLOUD_DATA_ADDR":                     lis.Addr().String(),
		"ACTIONS_ID_TOKEN_REQUEST_URL":                idToken.URL + "/token?api-version=2.0",
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN":              requestToken,
	}
}
