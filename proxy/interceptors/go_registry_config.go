package interceptors

import "strings"

type goRegistryConfig struct {
	Host   string
	Parser registryURLParser
}

type goRegistryConfigMap map[string]*goRegistryConfig

func (m goRegistryConfigMap) GetConfigForHostname(hostname string) *goRegistryConfig {
	if config, exists := m[hostname]; exists {
		return config
	}

	var best *goRegistryConfig
	bestLen := 0
	for endpoint, config := range m {
		if strings.HasSuffix(hostname, "."+endpoint) && len(endpoint) > bestLen {
			best = config
			bestLen = len(endpoint)
		}
	}

	return best
}

func (m goRegistryConfigMap) ContainsHostname(hostname string) bool {
	return m.GetConfigForHostname(hostname) != nil
}
