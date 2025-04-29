package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/safedep/pmg/pkg/models"
)

// RegistryClient defines the interface for making requests to a registry
type RegistryClient interface {
	// FetchPackageInfo fetches metadata for a specific package version
	FetchPackageInfo(ctx context.Context, pkg models.Package) (*models.PackageInfo, error)
	// GetLatestVersion fetches the latest version for a package
	GetLatestVersion(ctx context.Context, packageName string) (string, error)
}

// HttpRegistryClient is a basic HTTP client for registry APIs
type HttpRegistryClient struct {
	httpClient *http.Client
	urlFormat  string
	parser     func([]byte) (*models.PackageInfo, error)
}

// NewHttpRegistryClient creates a new HTTP registry client
func NewHttpRegistryClient(
	timeout time.Duration,
	urlFormat string,
	parser func([]byte) (*models.PackageInfo, error),
) *HttpRegistryClient {
	return &HttpRegistryClient{
		httpClient: &http.Client{Timeout: timeout},
		urlFormat:  urlFormat,
		parser:     parser,
	}
}

// FetchPackageInfo fetches package metadata from the registry
func (c *HttpRegistryClient) FetchPackageInfo(ctx context.Context, pkg models.Package) (*models.PackageInfo, error) {
	url := fmt.Sprintf(c.urlFormat, pkg.Name, pkg.Version)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry returned status: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	return c.parser(body)
}

// GetLatestVersion fetches the latest version for an NPM package
func (c *HttpRegistryClient) GetLatestVersion(ctx context.Context, packageName string) (string, error) {
	// For NPM, we can get latest version by querying the base package URL
	url := fmt.Sprintf("https://registry.npmjs.org/%s", packageName)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("registry returned status: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response body: %w", err)
	}

	// Parse the response to get the latest version
	var pkgData struct {
		DistTags struct {
			Latest string `json:"latest"`
		} `json:"dist-tags"`
	}

	if err := json.Unmarshal(body, &pkgData); err != nil {
		return "", fmt.Errorf("parsing package info: %w", err)
	}

	if pkgData.DistTags.Latest == "" {
		return "", fmt.Errorf("no latest version found for package %s", packageName)
	}

	return pkgData.DistTags.Latest, nil
}
