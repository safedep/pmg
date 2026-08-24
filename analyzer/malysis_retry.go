package analyzer

import (
	"context"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RetryConfig configures retries for transient backend errors. It is internal
// configuration with a safe default. It is not user-facing.
type RetryConfig struct {
	// MaxRetries is the number of extra attempts after the first attempt. A
	// value of 0 disables retries. The total attempt count is MaxRetries + 1.
	MaxRetries int

	// Backoff is the delay between attempts. A non-positive value retries with
	// no delay.
	Backoff time.Duration
}

// DefaultRetryConfig returns the default retry policy. It retries a transient
// backend error 2 times. This gives 3 attempts in total.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries: 2,
		Backoff:    200 * time.Millisecond,
	}
}

// malysisRetryAnalyzer retries the wrapped analyzer on a transient backend
// error. It does not change the verdict. A non-transient error and a verdict
// both return on the first attempt.
type malysisRetryAnalyzer struct {
	next   PackageVersionAnalyzer
	config RetryConfig
}

var _ PackageVersionAnalyzer = &malysisRetryAnalyzer{}

func newMalysisRetryAnalyzer(next PackageVersionAnalyzer, config RetryConfig) *malysisRetryAnalyzer {
	if config.MaxRetries < 0 {
		config.MaxRetries = 0
	}
	return &malysisRetryAnalyzer{next: next, config: config}
}

func (a *malysisRetryAnalyzer) Name() string {
	return a.next.Name()
}

func (a *malysisRetryAnalyzer) Analyze(ctx context.Context,
	packageVersion *packagev1.PackageVersion) (*PackageVersionAnalysisResult, error) {

	var result *PackageVersionAnalysisResult
	var err error

	for attempt := 0; attempt <= a.config.MaxRetries; attempt++ {
		result, err = a.next.Analyze(ctx, packageVersion)
		if err == nil || !isRetryableError(err) {
			return result, err
		}

		if attempt == a.config.MaxRetries {
			break
		}

		log.Debugf("Retrying analysis for %s@%s after transient error (attempt %d of %d): %v",
			packageVersion.GetPackage().GetName(), packageVersion.GetVersion(),
			attempt+1, a.config.MaxRetries, err)

		if a.config.Backoff > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(a.config.Backoff):
			}
		}
	}

	return result, err
}

// isRetryableError reports whether err is a transient backend error. A
// transient error is worth another attempt. status.FromError unwraps wrapped
// error chains since gRPC v1.75.0.
func isRetryableError(err error) bool {
	s, ok := status.FromError(err)
	if !ok {
		return false
	}

	switch s.Code() {
	case codes.DeadlineExceeded, codes.Unavailable:
		return true
	default:
		return false
	}
}
