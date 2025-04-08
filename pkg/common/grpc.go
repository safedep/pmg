package common

import (
	"fmt"
	"net/http"
	"os"

	drygrpc "github.com/safedep/dry/adapters/grpc"
	"google.golang.org/grpc"
)

func NewCloudClientConnection() (*grpc.ClientConn, error) {
	tok := os.Getenv("SAFEDEP_API_KEY")
	tenantId := os.Getenv("SAFEDEP_TENANT_ID")
	if tok == "" || tenantId == "" {
		return nil, fmt.Errorf("SAFEDEP_API_KEY and SAFEDEP_TENANT_ID must be set")
	}
	headers := http.Header{}
	headers.Set("x-tenant-id", tenantId)

	cc, err := newGrpcClient(headers, tok, "pmg-pkg-scan", "api.safedep.io", "443")
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client: %v", err)
	}
	return cc, nil
}

func newGrpcClient(headers http.Header, token, clientName, host, port string) (*grpc.ClientConn, error) {
	cc, err := drygrpc.GrpcClient(clientName, host, port, token, headers, []grpc.DialOption{})
	if err != nil {
		return nil, err
	}
	return cc, nil
}
