package registryurl

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

func Normalize(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}
	if !parsed.IsAbs() {
		return "", fmt.Errorf("URL must be absolute")
	}

	scheme := NormalizeScheme(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("URL scheme must be http or https")
	}
	if parsed.Host == "" || parsed.Hostname() == "" {
		return "", fmt.Errorf("URL host is required")
	}
	if parsed.User != nil {
		return "", fmt.Errorf("URL must not include credentials")
	}
	if parsed.RawQuery != "" || parsed.ForceQuery {
		return "", fmt.Errorf("URL must not include a query")
	}
	if parsed.Fragment != "" || strings.Contains(rawURL, "#") {
		return "", fmt.Errorf("URL must not include a fragment")
	}

	hostname := NormalizeHostname(parsed.Hostname())
	host := hostname
	if strings.Contains(hostname, ":") {
		host = "[" + hostname + "]"
	}

	port := parsed.Port()
	if port == "" && strings.HasSuffix(parsed.Host, ":") {
		return "", fmt.Errorf("URL port must be between 1 and 65535")
	}
	if port != "" {
		portNumber, err := strconv.ParseUint(port, 10, 16)
		if err != nil || portNumber == 0 {
			return "", fmt.Errorf("URL port must be between 1 and 65535")
		}
		port = strconv.Itoa(int(portNumber))
		if port != defaultPort(scheme) {
			host += ":" + port
		}
	}

	path := NormalizeBasePath(parsed.EscapedPath())
	return scheme + "://" + host + path, nil
}

func NormalizeScheme(scheme string) string {
	return strings.ToLower(scheme)
}

func NormalizeHostname(hostname string) string {
	return strings.ToLower(hostname)
}

func EffectivePort(scheme, port string) (string, bool) {
	if port == "" {
		port = defaultPort(NormalizeScheme(scheme))
		if port == "" {
			return "", false
		}
		return port, true
	}

	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return "", false
	}
	return strconv.Itoa(int(portNumber)), true
}

func NormalizeEscapedPath(path string) string {
	var normalized strings.Builder
	normalized.Grow(len(path))

	for index := 0; index < len(path); index++ {
		if path[index] == '%' && index+2 < len(path) {
			normalized.WriteByte('%')
			normalized.WriteString(strings.ToUpper(path[index+1 : index+3]))
			index += 2
			continue
		}
		normalized.WriteByte(path[index])
	}

	return normalized.String()
}

func NormalizeBasePath(path string) string {
	return strings.TrimRight(NormalizeEscapedPath(path), "/")
}

func defaultPort(scheme string) string {
	switch scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}
