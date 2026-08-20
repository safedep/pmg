package registryurl

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Normalize validates a registry endpoint URL and returns it in canonical
// form: lowercase scheme/host, default port elided, escaped-hex path
// uppercased, trailing slashes trimmed. It rejects anything that would
// never match real traffic (relative URLs, credentials, query, fragment,
// bad ports, unclean path segments).
func Normalize(rawURL string) (*url.URL, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL syntax or escaping")
	}
	if !parsed.IsAbs() {
		return nil, fmt.Errorf("URL must be absolute")
	}

	scheme := NormalizeScheme(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("URL scheme must be http or https")
	}
	if parsed.Host == "" || parsed.Hostname() == "" {
		return nil, fmt.Errorf("URL host is required")
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("URL must not include credentials")
	}
	if parsed.RawQuery != "" || parsed.ForceQuery {
		return nil, fmt.Errorf("URL must not include a query")
	}
	// Any '#' in the raw URL is the fragment delimiter (encoded %23 is
	// data), so this also covers a trailing empty fragment.
	if strings.Contains(rawURL, "#") {
		return nil, fmt.Errorf("URL must not include a fragment")
	}

	hostname := NormalizeHostname(parsed.Hostname())
	host := hostname
	if strings.Contains(hostname, ":") {
		host = "[" + hostname + "]"
	}

	port := parsed.Port()
	if port == "" && strings.HasSuffix(parsed.Host, ":") {
		return nil, fmt.Errorf("URL port must be between 1 and 65535")
	}
	effectivePort, valid := EffectivePort(scheme, port)
	if !valid {
		return nil, fmt.Errorf("URL port must be between 1 and 65535")
	}
	if effectivePort != defaultPort(scheme) {
		host += ":" + effectivePort
	}

	path := NormalizeBasePath(parsed.EscapedPath())
	if HasUncleanPathSegments(path) {
		return nil, fmt.Errorf("URL path must not contain empty or dot segments")
	}

	canonical, err := url.Parse(scheme + "://" + host + path)
	if err != nil {
		return nil, fmt.Errorf("invalid URL syntax or escaping")
	}
	return canonical, nil
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

// HasUncleanPathSegments reports whether an escaped path contains an empty
// or dot segment (including %2E forms). Servers resolve such paths into a
// different tree than a literal prefix match suggests, so endpoint base
// paths must not contain them and request paths containing them are left
// unmatched. The leading segment (before the first slash) and a trailing
// slash are not treated as empty segments.
func HasUncleanPathSegments(escapedPath string) bool {
	segments := strings.Split(escapedPath, "/")
	for i, segment := range segments {
		if segment == "" {
			if i != 0 && i != len(segments)-1 {
				return true
			}
			continue
		}
		if segment == "." || segment == ".." {
			return true
		}
		if decoded, err := url.PathUnescape(segment); err == nil && (decoded == "." || decoded == "..") {
			return true
		}
	}
	return false
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
