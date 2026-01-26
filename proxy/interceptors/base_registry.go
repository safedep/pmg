package interceptors

import (
	"context"
	"fmt"
	"net/http"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/eventlog"
	"github.com/safedep/pmg/proxy"
)

// baseRegistryInterceptor provides common functionality for registry interceptors
// It contains ecosystem-agnostic methods that can be reused by specific registry implementations
type baseRegistryInterceptor struct {
	analyzer         analyzer.PackageVersionAnalyzer
	cache            AnalysisCache
	statsCollector   *AnalysisStatsCollector
	confirmationChan chan *ConfirmationRequest
}

var _ proxy.Interceptor = (*baseRegistryInterceptor)(nil)

// Name returns a default name - should be overridden by specific implementations
func (b *baseRegistryInterceptor) Name() string {
	return "base-registry-interceptor"
}

// ShouldIntercept returns false by default - must be overridden by specific implementations
func (b *baseRegistryInterceptor) ShouldIntercept(ctx *proxy.RequestContext) bool {
	return false
}

// HandleRequest returns allow by default - should be overridden by specific implementations
func (b *baseRegistryInterceptor) HandleRequest(ctx *proxy.RequestContext) (*proxy.InterceptorResponse, error) {
	return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
}

// analyzePackage analyzes a package using the configured analyzer with caching
// This method is ecosystem-agnostic and can be used by any registry interceptor
func (b *baseRegistryInterceptor) analyzePackage(
	ctx *proxy.RequestContext,
	ecosystem packagev1.Ecosystem,
	packageName string,
	packageVersion string,
) (*analyzer.PackageVersionAnalysisResult, error) {
	// Check if package is trusted before analyzing
	pkgVersion := &packagev1.PackageVersion{
		Package: &packagev1.Package{
			Ecosystem: ecosystem,
			Name:      packageName,
		},
		Version: packageVersion,
	}

	if cfg := config.Get(); cfg.InsecureInstallation {
		log.Debugf("[%s] Skipping insecure installation", ctx.RequestID)

		// When insecure installation is enabled, we assume the package is trusted.
		eventlog.LogInstallTrustedAllowed(packageName, packageVersion, ecosystem.String())

		return &analyzer.PackageVersionAnalysisResult{
			PackageVersion: pkgVersion,
			Action:         analyzer.ActionAllow,
		}, nil
	}

	if config.IsTrustedPackage(pkgVersion) {
		log.Debugf("[%s] Skipping trusted package: %s/%s@%s",
			ctx.RequestID, ecosystem.String(), packageName, packageVersion)

		eventlog.LogInstallTrustedAllowed(packageName, packageVersion, ecosystem.String())

		return &analyzer.PackageVersionAnalysisResult{
			PackageVersion: pkgVersion,
			Action:         analyzer.ActionAllow,
		}, nil
	}

	if cached, ok := b.cache.Get(ecosystem.String(), packageName, packageVersion); ok {
		log.Debugf("[%s] Using cached analysis result for %s@%s", ctx.RequestID, packageName, packageVersion)
		return cached, nil
	}

	log.Debugf("[%s] Analyzing package %s@%s", ctx.RequestID, packageName, packageVersion)

	analysisCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := b.analyzer.Analyze(analysisCtx, pkgVersion)
	if err != nil {
		return nil, fmt.Errorf("analyzer failed: %w", err)
	}

	b.cache.Set(ecosystem.String(), packageName, packageVersion, result)

	log.Debugf("[%s] Analysis complete for %s@%s: action=%d", ctx.RequestID, packageName, packageVersion, result.Action)

	return result, nil
}

// handleAnalysisResult processes the analysis result and returns appropriate response action
// This method is ecosystem agnostic and handles the analysis result uniformly
func (b *baseRegistryInterceptor) handleAnalysisResult(
	ctx *proxy.RequestContext,
	ecosystem packagev1.Ecosystem,
	packageName string,
	packageVersion string,
	result *analyzer.PackageVersionAnalysisResult,
) (*proxy.InterceptorResponse, error) {
	switch result.Action {
	case analyzer.ActionBlock:
		log.Warnf("[%s] Blocking malicious package %s@%s", ctx.RequestID, packageName, packageVersion)

		eventlog.LogMalwareBlocked(packageName, packageVersion, ecosystem.String(), result.Summary, map[string]interface{}{
			"analysis_id":   result.AnalysisID,
			"reference_url": result.ReferenceURL,
		})

		if b.statsCollector != nil {
			b.statsCollector.RecordBlocked(result)
		}

		message := fmt.Sprintf("Malicious package blocked: %s/%s@%s\n\nReason: %s\n\nReference: %s",
			ecosystem.String(),
			packageName, packageVersion,
			result.Summary,
			result.ReferenceURL)

		return &proxy.InterceptorResponse{
			Action:       proxy.ActionBlock,
			BlockCode:    http.StatusForbidden,
			BlockMessage: message,
		}, nil

	case analyzer.ActionConfirm:
		log.Warnf("[%s] Package %s/%s@%s is suspicious, requesting user confirmation", ctx.RequestID, ecosystem.String(), packageName, packageVersion)

		confirmed, err := b.requestUserConfirmation(ctx, result)
		if err != nil {
			log.Errorf("[%s] Failed to get user confirmation: %v", ctx.RequestID, err)

			if b.statsCollector != nil {
				b.statsCollector.RecordBlocked(result)
			}

			return &proxy.InterceptorResponse{
				Action:       proxy.ActionBlock,
				BlockCode:    http.StatusForbidden,
				BlockMessage: fmt.Sprintf("Failed to get user confirmation for suspicious package %s/%s@%s", ecosystem.String(), packageName, packageVersion),
			}, nil
		}

		if !confirmed {
			log.Infof("[%s] User declined installation of suspicious package %s/%s@%s", ctx.RequestID, ecosystem.String(), packageName, packageVersion)

			eventlog.LogMalwareBlocked(packageName, packageVersion, ecosystem.String(), result.Summary, map[string]interface{}{
				"analysis_id":   result.AnalysisID,
				"reference_url": result.ReferenceURL,
			})

			if b.statsCollector != nil {
				b.statsCollector.RecordBlocked(result)
			}

			message := fmt.Sprintf("Installation blocked by user: %s/%s@%s\n\nReason: %s\n\nReference: %s",
				ecosystem.String(),
				packageName, packageVersion,
				result.Summary,
				result.ReferenceURL)

			return &proxy.InterceptorResponse{
				Action:       proxy.ActionBlock,
				BlockCode:    http.StatusForbidden,
				BlockMessage: message,
			}, nil
		}

		eventlog.LogMalwareConfirmed(packageName, packageVersion, ecosystem.String())
		eventlog.LogInstallAllowed(packageName, packageVersion, ecosystem.String(), 1)

		if b.statsCollector != nil {
			b.statsCollector.RecordConfirmed(result)
		}

		log.Infof("[%s] User confirmed installation of suspicious package %s/%s@%s", ctx.RequestID, ecosystem.String(), packageName, packageVersion)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil

	case analyzer.ActionAllow:
		eventlog.LogInstallAllowed(packageName, packageVersion, ecosystem.String(), 1)

		if b.statsCollector != nil {
			b.statsCollector.RecordAllowed(result)
		}

		log.Debugf("[%s] Package %s/%s@%s is safe, allowing request", ctx.RequestID, ecosystem.String(), packageName, packageVersion)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil

	default:
		eventlog.LogInstallAllowed(packageName, packageVersion, ecosystem.String(), 1)

		if b.statsCollector != nil {
			b.statsCollector.RecordAllowed(result)
		}

		log.Warnf("[%s] Unknown analysis action %d for package %s/%s@%s, allowing by default", ctx.RequestID, result.Action, ecosystem.String(), packageName, packageVersion)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}
}

// requestUserConfirmation sends a confirmation request and blocks waiting for user response
func (b *baseRegistryInterceptor) requestUserConfirmation(
	ctx *proxy.RequestContext,
	result *analyzer.PackageVersionAnalysisResult,
) (bool, error) {
	req := NewConfirmationRequest(result.PackageVersion, result)

	select {
	case b.confirmationChan <- req:
	case <-time.After(5 * time.Second):
		return false, fmt.Errorf("timeout sending confirmation request")
	}

	// Block waiting for user response
	// Producer is responsible for closing the response channel to prevent goroutine leaks.
	select {
	case confirmed := <-req.ResponseChan:
		return confirmed, nil
	case <-time.After(5 * time.Minute):
		return false, fmt.Errorf("timeout waiting for user confirmation")
	}
}
