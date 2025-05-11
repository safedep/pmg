package common

import (
	"fmt"
	"net/http"

	drygrpc "github.com/safedep/dry/adapters/grpc"
	"google.golang.org/grpc"
)

func NewCloudClientConnection() (*grpc.ClientConn, error) {
	cc, err := newGrpcClient(http.Header{}, "", "pmg-pkg-scan", "community-api.safedep.io", "443")
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
