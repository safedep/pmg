package config

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateProxyRegistries(t *testing.T) {
	tests := []struct {
		name       string
		registries []ProxyRegistryConfig
		wantErr    string
	}{
		{
			name: "valid npm registry",
			registries: []ProxyRegistryConfig{{
				Name:      "company-npm",
				Ecosystem: "npm",
				Endpoints: []ProxyRegistryEndpointConfig{{
					URL: "https://packages.example.test/artifactory/api/npm/team/",
				}},
			}},
		},
		{
			name: "valid pypi registry with escaped path",
			registries: []ProxyRegistryConfig{{
				Name:      "company-pypi",
				Ecosystem: "pypi",
				Endpoints: []ProxyRegistryEndpointConfig{{
					URL: "https://packages.example.test/simple/%2Fteam/",
				}},
			}},
		},
		{
			name: "duplicate trimmed name",
			registries: []ProxyRegistryConfig{
				{Name: "packages", Ecosystem: "npm", Endpoints: []ProxyRegistryEndpointConfig{{URL: "https://npm.example.test/"}}},
				{Name: " packages ", Ecosystem: "pypi", Endpoints: []ProxyRegistryEndpointConfig{{URL: "https://pypi.example.test/simple"}}},
			},
			wantErr: `duplicate proxy registry name "packages"`,
		},
		{
			name: "empty name",
			registries: []ProxyRegistryConfig{{
				Ecosystem: "npm",
				Endpoints: []ProxyRegistryEndpointConfig{{URL: "https://npm.example.test/"}},
			}},
			wantErr: "proxy.registries[0].name is required",
		},
		{
			name: "whitespace name",
			registries: []ProxyRegistryConfig{{
				Name:      " \t ",
				Ecosystem: "npm",
				Endpoints: []ProxyRegistryEndpointConfig{{URL: "https://npm.example.test/"}},
			}},
			wantErr: "proxy.registries[0].name is required",
		},
		{
			name: "unsupported ecosystem",
			registries: []ProxyRegistryConfig{{
				Name:      "packages",
				Ecosystem: "maven",
				Endpoints: []ProxyRegistryEndpointConfig{{URL: "https://packages.example.test/"}},
			}},
			wantErr: `proxy registry "packages" has unsupported ecosystem "maven"`,
		},
		{
			name: "missing ecosystem",
			registries: []ProxyRegistryConfig{{
				Name:      "packages",
				Endpoints: []ProxyRegistryEndpointConfig{{URL: "https://packages.example.test/"}},
			}},
			wantErr: `proxy registry "packages" has unsupported ecosystem ""`,
		},
		{
			name: "no endpoints",
			registries: []ProxyRegistryConfig{{
				Name:      "packages",
				Ecosystem: "npm",
			}},
			wantErr: `proxy registry "packages" must define at least one endpoint`,
		},
		{
			name: "empty endpoint url",
			registries: []ProxyRegistryConfig{{
				Name:      "packages",
				Ecosystem: "npm",
				Endpoints: []ProxyRegistryEndpointConfig{{
					URL: "",
				}},
			}},
			wantErr: `proxy registry "packages" endpoint 0: URL must be absolute`,
		},
		{
			name: "relative endpoint url",
			registries: []ProxyRegistryConfig{{
				Name:      "packages",
				Ecosystem: "npm",
				Endpoints: []ProxyRegistryEndpointConfig{{
					URL: "/npm",
				}},
			}},
			wantErr: `proxy registry "packages" endpoint 0: URL must be absolute`,
		},
		{
			name: "endpoint url without host",
			registries: []ProxyRegistryConfig{{
				Name:      "packages",
				Ecosystem: "npm",
				Endpoints: []ProxyRegistryEndpointConfig{{
					URL: "https:/npm",
				}},
			}},
			wantErr: `proxy registry "packages" endpoint 0: URL host is required`,
		},
		{
			name: "unsupported endpoint scheme",
			registries: []ProxyRegistryConfig{{
				Name:      "packages",
				Ecosystem: "npm",
				Endpoints: []ProxyRegistryEndpointConfig{{
					URL: "ftp://packages.example.test/npm",
				}},
			}},
			wantErr: `proxy registry "packages" endpoint 0: URL scheme must be http or https`,
		},
		{
			name: "endpoint url credentials",
			registries: []ProxyRegistryConfig{{
				Name:      "packages",
				Ecosystem: "npm",
				Endpoints: []ProxyRegistryEndpointConfig{{
					URL: "https://user:password@packages.example.test/npm",
				}},
			}},
			wantErr: `proxy registry "packages" endpoint 0: URL must not include credentials`,
		},
		{
			name: "endpoint url query",
			registries: []ProxyRegistryConfig{{
				Name:      "packages",
				Ecosystem: "npm",
				Endpoints: []ProxyRegistryEndpointConfig{{
					URL: "https://packages.example.test/npm?token=value",
				}},
			}},
			wantErr: `proxy registry "packages" endpoint 0: URL must not include a query`,
		},
		{
			name: "endpoint url fragment",
			registries: []ProxyRegistryConfig{{
				Name:      "packages",
				Ecosystem: "npm",
				Endpoints: []ProxyRegistryEndpointConfig{{
					URL: "https://packages.example.test/npm#fragment",
				}},
			}},
			wantErr: `proxy registry "packages" endpoint 0: URL must not include a fragment`,
		},
		{
			name: "duplicate normalized endpoint across registries",
			registries: []ProxyRegistryConfig{
				{Name: "npm", Ecosystem: "npm", Endpoints: []ProxyRegistryEndpointConfig{{URL: "HTTP://PACKAGES.EXAMPLE.TEST:80/npm/"}}},
				{Name: "pypi", Ecosystem: "pypi", Endpoints: []ProxyRegistryEndpointConfig{{URL: "http://packages.example.test/npm"}}},
			},
			wantErr: `proxy registry endpoint "http://packages.example.test/npm" is already assigned to "npm"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProxyRegistries(tt.registries)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestProxyRegistriesConfig(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader(`
proxy:
  registries:
    - name: company-npm
      ecosystem: npm
      endpoints:
        - url: https://packages.example.test/npm
    - name: company-pypi
      ecosystem: pypi
      endpoints:
        - url: https://packages.example.test/simple
`)))

	var cfg Config
	require.NoError(t, v.Unmarshal(&cfg))

	require.Len(t, cfg.Proxy.Registries, 2)
	assert.Equal(t, ProxyRegistryConfig{
		Name:      "company-npm",
		Ecosystem: "npm",
		Endpoints: []ProxyRegistryEndpointConfig{{URL: "https://packages.example.test/npm"}},
	}, cfg.Proxy.Registries[0])
	assert.Equal(t, ProxyRegistryConfig{
		Name:      "company-pypi",
		Ecosystem: "pypi",
		Endpoints: []ProxyRegistryEndpointConfig{{URL: "https://packages.example.test/simple"}},
	}, cfg.Proxy.Registries[1])
}
