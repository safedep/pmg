package utils

import (
	"fmt"
	"os"
	"strings"
)

func ApiKey() string {
	return os.Getenv("SAFEDEP_API_KEY")
}

func TenantDomain() string {
	return os.Getenv("SAFEDEP_TENANT_ID")
}

func NpmAuthToken() string {
	return os.Getenv("NPM_AUTH_TOKEN")
}

func ValidateEnvVars() error {
	apiKey := ApiKey()
	tenantId := TenantDomain()
	var missingVars []string

	if apiKey == "" {
		missingVars = append(missingVars, "SAFEDEP_API_KEY")
	}
	if tenantId == "" {
		missingVars = append(missingVars, "SAFEDEP_TENANT_ID")
	}

	if len(missingVars) > 0 {
		return fmt.Errorf(`
SafeDep configuration incomplete

Missing environment variables:
  %s

To enable package scanning:
  1. Export these variables in your terminal:
     export %s=your_api_key
     export %s=your_tenant_id
  2. Or add them to your shell profile file

For more information, visit: https://docs.safedep.io/cloud/quickstart
`, strings.Join(missingVars, "\n  "), missingVars[0], missingVars[len(missingVars)-1])
	}

	return nil
}
