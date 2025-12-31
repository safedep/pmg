package main

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/proxy"
)

type malysisInterceptor struct {
	domains              []string
	malysisQueryAnalyzer analyzer.PackageVersionAnalyzer
}

func newMalysisInterceptor(analyzer analyzer.PackageVersionAnalyzer) *malysisInterceptor {
	return &malysisInterceptor{
		malysisQueryAnalyzer: analyzer,
		domains: []string{
			"registry.npmjs.org",
			"registry.yarnpkg.com",
			"pypi.org",
			"files.pythonhosted.org",
		},
	}
}

func (m *malysisInterceptor) Name() string {
	return "logging-interceptor"
}

func (m *malysisInterceptor) ShouldIntercept(ctx *proxy.RequestContext) bool {
	return slices.Contains(m.domains, ctx.Hostname)
}

// parseNpmTarballURL parses tarball URLs such as
//
//	https://registry.npmjs.org/send/-/send-1.2.1.tgz
//
// and returns a PackageVersion with Ecosystem_NPM, Name and Version set.
//
// The parser:
// - extracts the filename from the URL path
// - strips common extensions (.tgz, .tar.gz)
// - finds a semver-like suffix in the filename and treats it as the version
// - derives the package name as the filename without the version suffix
// - attempts to detect scoped package names from earlier path segments (e.g. @scope/pkg)
func parseNpmTarballURL(raw string) (*packagev1.PackageVersion, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse url: %w", err)
	}

	filename := path.Base(u.Path) // e.g. send-1.2.1.tgz
	name := filename
	if strings.HasSuffix(name, ".tgz") {
		name = strings.TrimSuffix(name, ".tgz")
	} else if strings.HasSuffix(name, ".tar.gz") {
		name = strings.TrimSuffix(name, ".tar.gz")
	}

	// Capture semver-like version at the end of the filename.
	// Examples matched: 1.2.3, 1.2.3-beta.1, 1.2.3+meta, 1.2.3-beta.1+meta
	re := regexp.MustCompile(`-(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]*)?)$`)
	m := re.FindStringSubmatch(name)
	if len(m) < 2 {
		return nil, fmt.Errorf("version not found in filename %s", filename)
	}
	version := m[1]
	pkgName := strings.TrimSuffix(name, "-"+version)

	// Try to detect scoped package name from the path segments, e.g.
	// /@scope%2Fpkg/-/pkg-1.0.0.tgz  -> segment "@scope%2Fpkg"
	// decode any percent-encoded segments and prefer a decoded value that contains "/"
	seg := strings.Split(u.Path, "/")
	for _, s := range seg {
		if strings.Contains(s, "%2F") || strings.Contains(s, "%2f") || strings.HasPrefix(s, "@") {
			dec, err := url.PathUnescape(s)
			if err == nil && strings.Contains(dec, "/") {
				// dec is like "@scope/pkg"
				pkgName = dec
				break
			}
			if err == nil && strings.HasPrefix(dec, "@") {
				// fallback: keep the decoded @scope if present
				pkgName = dec
				break
			}
		}
	}

	pv := &packagev1.PackageVersion{
		Package: &packagev1.Package{
			Name:      pkgName,
			Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
		},
		Version: version,
	}
	return pv, nil
}

func (m *malysisInterceptor) HandleRequest(ctx *proxy.RequestContext) (*proxy.InterceptorResponse, error) {

	url := ctx.URL.String()
	isTarball := strings.Contains(url, "tgz")

	if !isTarball {
		return &proxy.InterceptorResponse{
			Action: proxy.ActionAllow,
		}, nil
	}

	// Parse the tarball URL into a PackageVersion and attach it to the request context
	pv, err := parseNpmTarballURL(url)
	if err != nil {
		fmt.Printf("Failed to parse npm tarball [%s] with error: %s", url, err.Error())
		return &proxy.InterceptorResponse{
			Action: proxy.ActionAllow,
		}, nil
	}

	result, err := m.malysisQueryAnalyzer.Analyze(context.Background(), pv)
	if err != nil {
		fmt.Printf("failed to analyse package %s with error %s:", pv.Package.Name, err.Error())
		return &proxy.InterceptorResponse{
			Action: proxy.ActionAllow,
		}, nil
	}

	switch result.Action {
	case analyzer.ActionAllow:
		fmt.Printf("Package %s@%s -> action: ALLOW\n", pv.Package.Name, pv.Version)
		return &proxy.InterceptorResponse{
			Action: proxy.ActionAllow,
		}, nil

	case analyzer.ActionConfirm:
		fmt.Printf("Package %s@%s -> action: CONFIRM (mapping to BLOCK)\n", pv.Package.Name, pv.Version)
		return &proxy.InterceptorResponse{
			Action: proxy.ActionBlock,
		}, nil

	case analyzer.ActionBlock:
		fmt.Printf("Package %s@%s -> action: BLOCK\n", pv.Package.Name, pv.Version)
		return &proxy.InterceptorResponse{
			Action: proxy.ActionBlock,
		}, nil

	default:
		fmt.Printf("Package %s@%s -> action: UNKNOWN (default to ALLOW)\n", pv.Package.Name, pv.Version)
		return &proxy.InterceptorResponse{
			Action: proxy.ActionAllow,
		}, nil

	}
}
