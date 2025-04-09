package utils

import "os"

func ApiKey() string {
	return os.Getenv("SAFEDEP_API_KEY")
}

func TenantDomain() string {
	return os.Getenv("SAFEDEP_TENANT_ID")
}

func NpmAuthToken() string {
	return os.Getenv("NPM_AUTH_TOKEN")
}
