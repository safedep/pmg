package interceptors

import (
	"context"
	"fmt"
	"net/http"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/guard"
	"github.com/safedep/pmg/proxy"
)

// baseRegistryInterceptor provides common functionality for registry interceptors
// It contains ecosystem-agnostic methods that can be reused by specific registry implementations
type baseRegistryInterceptor struct {
	analyzer         analyzer.PackageVersionAnalyzer
	cache            AnalysisCache
	confirmationChan chan *ConfirmationRequest
	interaction      guard.PackageManagerGuardInteraction
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
	// Check cache first
	if cached, ok := b.cache.Get(ecosystem.String(), packageName, packageVersion); ok {
		log.Debugf("[%s] Using cached analysis result for %s@%s", ctx.RequestID, packageName, packageVersion)
		return cached, nil
	}

	// Create package version object for analysis
	pkgVersion := &packagev1.PackageVersion{
		Package: &packagev1.Package{
			Ecosystem: ecosystem,
			Name:      packageName,
		},
		Version: packageVersion,
	}

	log.Debugf("[%s] Analyzing package %s@%s", ctx.RequestID, packageName, packageVersion)

	// Set status to indicate analysis is in progress
	if b.interaction.SetStatus != nil {
		b.interaction.SetStatus(fmt.Sprintf("Analyzing %s@%s...", packageName, packageVersion))
	}

	// Analyze the package with timeout
	analysisCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := b.analyzer.Analyze(analysisCtx, pkgVersion)
	if err != nil {
		if b.interaction.ClearStatus != nil {
			b.interaction.ClearStatus()
		}

		return nil, fmt.Errorf("analyzer failed: %w", err)
	}

	if b.interaction.ClearStatus != nil {
		b.interaction.ClearStatus()
	}

	// Cache the result
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
		// Confirmed malicious package - block immediately
		log.Warnf("[%s] Blocking malicious package %s@%s", ctx.RequestID, packageName, packageVersion)

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
		// Suspicious package - prompt user for confirmation
		log.Warnf("[%s] Package %s/%s@%s is suspicious, requesting user confirmation", ctx.RequestID, ecosystem.String(), packageName, packageVersion)

		confirmed, err := b.requestUserConfirmation(ctx, result)
		if err != nil {
			log.Errorf("[%s] Failed to get user confirmation: %v", ctx.RequestID, err)
			// On error, block the package to be safe
			return &proxy.InterceptorResponse{
				Action:       proxy.ActionBlock,
				BlockCode:    http.StatusForbidden,
				BlockMessage: fmt.Sprintf("Failed to get user confirmation for suspicious package %s/%s@%s", ecosystem.String(), packageName, packageVersion),
			}, nil
		}

		if !confirmed {
			// User declined installation
			log.Infof("[%s] User declined installation of suspicious package %s/%s@%s", ctx.RequestID, ecosystem.String(), packageName, packageVersion)

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

		// User confirmed installation
		log.Infof("[%s] User confirmed installation of suspicious package %s/%s@%s", ctx.RequestID, ecosystem.String(), packageName, packageVersion)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil

	case analyzer.ActionAllow:
		// Package is safe - allow the request
		log.Debugf("[%s] Package %s/%s@%s is safe, allowing request", ctx.RequestID, ecosystem.String(), packageName, packageVersion)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil

	default:
		// Unknown action - allow by default (fail-open)
		log.Warnf("[%s] Unknown analysis action %d for package %s/%s@%s, allowing by default", ctx.RequestID, result.Action, ecosystem.String(), packageName, packageVersion)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}
}

// requestUserConfirmation sends a confirmation request and blocks waiting for user response
func (b *baseRegistryInterceptor) requestUserConfirmation(
	ctx *proxy.RequestContext,
	result *analyzer.PackageVersionAnalysisResult,
) (bool, error) {
	// Create confirmation request with response channel
	req := NewConfirmationRequest(result.PackageVersion, result)

	// Send request to confirmation handler
	select {
	case b.confirmationChan <- req:
		// Request sent successfully
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
