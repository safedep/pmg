package analyser

import (
	"fmt"

	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/malysis/v1/malysisv1grpc"
	"github.com/safedep/pmg/pkg/common"
)

func GetMalwareAnalysisClient() (malysisv1grpc.MalwareAnalysisServiceClient, error) {
	cc, err := common.NewCloudClientConnection()
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client: %v", err)
	}
	return malysisv1grpc.NewMalwareAnalysisServiceClient(cc), nil
}
