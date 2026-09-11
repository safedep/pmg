package interceptors

import (
	"regexp"
	"strings"
)

var pypiVersionPattern = regexp.MustCompile(`(?i)^v?(?:(?P<epoch>[0-9]+)!)?` +
	`(?P<release>[0-9]+(?:\.[0-9]+)*)` +
	`(?:[._-]?(?P<pre>a|b|c|rc|alpha|beta|pre|preview)[._-]?(?P<preN>[0-9]+)?)?` +
	`(?:-(?P<postImplicit>[0-9]+)|[._-]?(?P<post>post|rev|r)[._-]?(?P<postN>[0-9]+)?)?` +
	`(?:[._-]?(?P<dev>dev)[._-]?(?P<devN>[0-9]+)?)?` +
	`(?:\+(?P<local>[a-z0-9]+(?:[._-][a-z0-9]+)*))?$`)

// normalizePypiVersion follows Python's str(Version(...)), which preserves release trailing zeros.
func normalizePypiVersion(version string) (string, bool) {
	matches := pypiVersionPattern.FindStringSubmatch(strings.TrimSpace(version))
	if matches == nil {
		return "", false
	}
	part := func(name string) string {
		return strings.ToLower(matches[pypiVersionPattern.SubexpIndex(name)])
	}

	release := strings.Split(part("release"), ".")
	for i := range release {
		release[i] = normalizePypiNumber(release[i])
	}
	result := strings.Join(release, ".")
	if epoch := normalizePypiNumber(part("epoch")); epoch != "0" {
		result = epoch + "!" + result
	}
	if pre := part("pre"); pre != "" {
		switch pre {
		case "alpha":
			pre = "a"
		case "beta":
			pre = "b"
		case "c", "pre", "preview":
			pre = "rc"
		}
		result += pre + normalizePypiNumber(part("preN"))
	}
	if implicit := part("postImplicit"); implicit != "" {
		result += ".post" + normalizePypiNumber(implicit)
	} else if part("post") != "" {
		result += ".post" + normalizePypiNumber(part("postN"))
	}
	if part("dev") != "" {
		result += ".dev" + normalizePypiNumber(part("devN"))
	}
	if local := part("local"); local != "" {
		segments := strings.FieldsFunc(local, func(r rune) bool { return r == '.' || r == '_' || r == '-' })
		for i, segment := range segments {
			if strings.Trim(segment, "0123456789") == "" {
				segments[i] = normalizePypiNumber(segment)
			}
		}
		result += "+" + strings.Join(segments, ".")
	}
	return result, true
}

func normalizePypiNumber(number string) string {
	number = strings.TrimLeft(number, "0")
	if number == "" {
		return "0"
	}
	return number
}
