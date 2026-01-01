package interceptors

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/guard"
	"github.com/safedep/pmg/proxy"
)

const (
	ecosystemNpm = "npm"
)

var (
	npmRegistryDomains = []string{
		"registry.npmjs.org",
		"registry.yarnpkg.com",
	}
)

// NpmRegistryInterceptor intercepts NPM registry requests and analyzes packages for malware
type NpmRegistryInterceptor struct {
	analyzer         analyzer.PackageVersionAnalyzer
	cache            AnalysisCache
	confirmationChan chan *ConfirmationRequest
	interaction      guard.PackageManagerGuardInteraction
}

var _ proxy.Interceptor = (*NpmRegistryInterceptor)(nil)

// NewNpmRegistryInterceptor creates a new NPM registry interceptor
func NewNpmRegistryInterceptor(
	analyzer analyzer.PackageVersionAnalyzer,
	cache AnalysisCache,
	confirmationChan chan *ConfirmationRequest,
	interaction guard.PackageManagerGuardInteraction,
) *NpmRegistryInterceptor {
	return &NpmRegistryInterceptor{
		analyzer:         analyzer,
		cache:            cache,
		confirmationChan: confirmationChan,
		interaction:      interaction,
	}
}

// Name returns the interceptor name for logging
func (i *NpmRegistryInterceptor) Name() string {
	return "npm-registry-interceptor"
}

// ShouldIntercept determines if this interceptor should handle the given request
func (i *NpmRegistryInterceptor) ShouldIntercept(ctx *proxy.RequestContext) bool {
	for _, domain := range npmRegistryDomains {
		if ctx.Hostname == domain || strings.HasSuffix(ctx.Hostname, "."+domain) {
			return true
		}
	}

	return false
}

// HandleRequest processes the request and returns response action
// We take a fail-open approach here, allowing requests that we can't parse the package information from the URL.
func (i *NpmRegistryInterceptor) HandleRequest(ctx *proxy.RequestContext) (*proxy.InterceptorResponse, error) {
	log.Debugf("[%s] Handling NPM registry request: %s", ctx.RequestID, ctx.URL.Path)

	pkgInfo, err := parseNpmRegistryURL(ctx.URL.Path)
	if err != nil {
		log.Warnf("[%s] Failed to parse NPM registry URL %s: %v", ctx.RequestID, ctx.URL.Path, err)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	// Only analyze tarball downloads (these have a specific version)
	// Metadata requests (without version) are allowed through
	if !pkgInfo.IsTarball {
		log.Debugf("[%s] Skipping analysis for metadata request: %s", ctx.RequestID, pkgInfo.Name)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	result, err := i.analyzePackage(ctx, pkgInfo)
	if err != nil {
		log.Errorf("[%s] Failed to analyze package %s@%s: %v", ctx.RequestID, pkgInfo.Name, pkgInfo.Version, err)
		// On analysis error, allow the package (fail-open for usability)
		if i.interaction.ShowWarning != nil {
			i.interaction.ShowWarning(fmt.Sprintf("Warning: Failed to analyze package %s@%s: %v", pkgInfo.Name, pkgInfo.Version, err))
		}

		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	// Handle the analysis result
	return i.handleAnalysisResult(ctx, pkgInfo, result)
}

// analyzePackage analyzes a package using the configured analyzer with caching
func (i *NpmRegistryInterceptor) analyzePackage(ctx *proxy.RequestContext, pkgInfo *npmPackageInfo) (*analyzer.PackageVersionAnalysisResult, error) {
	// Check cache first
	if cached, ok := i.cache.Get(ecosystemNpm, pkgInfo.Name, pkgInfo.Version); ok {
		log.Debugf("[%s] Using cached analysis result for %s@%s", ctx.RequestID, pkgInfo.Name, pkgInfo.Version)
		return cached, nil
	}

	// Create package version object for analysis
	pkgVersion := &packagev1.PackageVersion{
		Package: &packagev1.Package{
			Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
			Name:      pkgInfo.Name,
		},
		Version: pkgInfo.Version,
	}

	log.Debugf("[%s] Analyzing package %s@%s", ctx.RequestID, pkgInfo.Name, pkgInfo.Version)

	// Set status to indicate analysis is in progress
	if i.interaction.SetStatus != nil {
		i.interaction.SetStatus(fmt.Sprintf("Analyzing %s@%s...", pkgInfo.Name, pkgInfo.Version))
	}

	// Analyze the package with timeout
	analysisCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := i.analyzer.Analyze(analysisCtx, pkgVersion)
	if err != nil {
		if i.interaction.ClearStatus != nil {
			i.interaction.ClearStatus()
		}
		return nil, fmt.Errorf("analyzer failed: %w", err)
	}

	if i.interaction.ClearStatus != nil {
		i.interaction.ClearStatus()
	}

	// Cache the result
	i.cache.Set(ecosystemNpm, pkgInfo.Name, pkgInfo.Version, result)

	log.Debugf("[%s] Analysis complete for %s@%s: action=%d", ctx.RequestID, pkgInfo.Name, pkgInfo.Version, result.Action)

	return result, nil
}

// handleAnalysisResult processes the analysis result and returns appropriate response action
func (i *NpmRegistryInterceptor) handleAnalysisResult(
	ctx *proxy.RequestContext,
	pkgInfo *npmPackageInfo,
	result *analyzer.PackageVersionAnalysisResult,
) (*proxy.InterceptorResponse, error) {
	switch result.Action {
	case analyzer.ActionBlock:
		// Confirmed malicious package - block immediately
		log.Warnf("[%s] Blocking malicious package %s@%s", ctx.RequestID, pkgInfo.Name, pkgInfo.Version)

		message := fmt.Sprintf("Malicious package blocked: %s@%s\n\nReason: %s\n\nReference: %s",
			pkgInfo.Name, pkgInfo.Version,
			result.Summary,
			result.ReferenceURL)

		return &proxy.InterceptorResponse{
			Action:       proxy.ActionBlock,
			BlockCode:    http.StatusForbidden,
			BlockMessage: message,
		}, nil

	case analyzer.ActionConfirm:
		// Suspicious package - prompt user for confirmation
		log.Warnf("[%s] Package %s@%s is suspicious, requesting user confirmation", ctx.RequestID, pkgInfo.Name, pkgInfo.Version)

		confirmed, err := i.requestUserConfirmation(ctx, result)
		if err != nil {
			log.Errorf("[%s] Failed to get user confirmation: %v", ctx.RequestID, err)
			// On error, block the package to be safe
			return &proxy.InterceptorResponse{
				Action:       proxy.ActionBlock,
				BlockCode:    http.StatusForbidden,
				BlockMessage: fmt.Sprintf("Failed to get user confirmation for suspicious package %s@%s", pkgInfo.Name, pkgInfo.Version),
			}, nil
		}

		if !confirmed {
			// User declined installation
			log.Infof("[%s] User declined installation of suspicious package %s@%s", ctx.RequestID, pkgInfo.Name, pkgInfo.Version)

			message := fmt.Sprintf("Installation blocked by user: %s@%s\n\nReason: %s\n\nReference: %s",
				pkgInfo.Name, pkgInfo.Version,
				result.Summary,
				result.ReferenceURL)

			return &proxy.InterceptorResponse{
				Action:       proxy.ActionBlock,
				BlockCode:    http.StatusForbidden,
				BlockMessage: message,
			}, nil
		}

		// User confirmed installation
		log.Infof("[%s] User confirmed installation of suspicious package %s@%s", ctx.RequestID, pkgInfo.Name, pkgInfo.Version)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil

	case analyzer.ActionAllow:
		// Package is safe - allow the request
		log.Debugf("[%s] Package %s@%s is safe, allowing request", ctx.RequestID, pkgInfo.Name, pkgInfo.Version)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil

	default:
		// Unknown action - allow by default (fail-open)
		log.Warnf("[%s] Unknown analysis action %d for package %s@%s, allowing by default", ctx.RequestID, result.Action, pkgInfo.Name, pkgInfo.Version)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}
}

// requestUserConfirmation sends a confirmation request and blocks waiting for user response
func (i *NpmRegistryInterceptor) requestUserConfirmation(
	ctx *proxy.RequestContext,
	result *analyzer.PackageVersionAnalysisResult,
) (bool, error) {
	// Create confirmation request with response channel
	req := NewConfirmationRequest(result.PackageVersion, result)

	// Send request to confirmation handler
	select {
	case i.confirmationChan <- req:
		// Request sent successfully
	case <-time.After(5 * time.Second):
		return false, fmt.Errorf("timeout sending confirmation request")
	}

	// Block waiting for user response
	select {
	case confirmed := <-req.ResponseChan:
		close(req.ResponseChan)
		return confirmed, nil
	case <-time.After(5 * time.Minute):
		// Timeout waiting for user response - block the package to be safe
		close(req.ResponseChan)
		return false, fmt.Errorf("timeout waiting for user confirmation")
	}
}
