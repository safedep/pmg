package analyser

import (
	"fmt"
	"net/http"
	"os"

	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/malysis/v1/malysisv1grpc"
	drygrpc "github.com/safedep/dry/adapters/grpc"
	"google.golang.org/grpc"
)

func GetMalwareAnalysisClient() (malysisv1grpc.MalwareAnalysisServiceClient, error) {
	tok := os.Getenv("SAFEDEP_API_KEY")
	tenantId := os.Getenv("SAFEDEP_TENANT_ID")
	if tok == "" || tenantId == "" {
		return nil, fmt.Errorf("SAFEDEP_API_KEY and SAFEDEP_TENANT_ID must be set")
	}
	headers := http.Header{}
	headers.Set("x-tenant-id", tenantId)
	cc, err := drygrpc.GrpcClient("pmg-pkg-scan", "api.safedep.io", "443",
		tok, headers, []grpc.DialOption{})
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client: %v", err)
	}
	return malysisv1grpc.NewMalwareAnalysisServiceClient(cc), nil
}
