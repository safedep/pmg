package utils

import (
	"regexp"
	"strings"
)

var (
	headerBulletRegex   = regexp.MustCompile(`(?m)^(#{1,6}\s+|[-*]\s{1,}|\d+\.\s+|>\s+)`)
	inlineCodeRegex     = regexp.MustCompile("`{1,3}([^`]*)`{1,3}")
	horizontalRuleRegex = regexp.MustCompile(`(?m)^\s*(-{3,}|\*{3,}|\_{3,})\s*$`)
	boldItalicRegex     = regexp.MustCompile(`(?:\*\*\*|___)(.*?)(?:\*\*\*|___)`)
	boldRegex           = regexp.MustCompile(`(?:\*\*|__)(.*?)(?:\*\*|__)`)
	italicRegex         = regexp.MustCompile(`(?:\*|_)(.*?)(?:\*|_)`)
	strikethroughRegex  = regexp.MustCompile(`~~([^~]+)~~`)
	inlineLinkRegex     = regexp.MustCompile(`\[([^\]]+)\]\((\S+?)\)`)
	imageRegex          = regexp.MustCompile(`!\[([^\]]*)\]\((\S+?)\)`)
	extraSpacesRegex    = regexp.MustCompile(`\s+`)
)

func removeMarkdown(text string) string {
	// Remove bold italic (***bolditalic*** or ___bolditalic___)
	text = boldItalicRegex.ReplaceAllString(text, "$1")

	// Remove bold (**bold** or __bold__)
	text = boldRegex.ReplaceAllString(text, "$1")

	// Remove italic (*italic* or _italic_)
	text = italicRegex.ReplaceAllString(text, "$1")

	// Remove strikethrough (~~text~~)
	text = strikethroughRegex.ReplaceAllString(text, "$1")

	// Remove inline code (`code`)
	text = inlineCodeRegex.ReplaceAllString(text, "$1")

	// Remove links [text](url)
	text = inlineLinkRegex.ReplaceAllString(text, "$1")

	// Remove images ![alt](url)
	text = imageRegex.ReplaceAllString(text, "$1")

	// Remove horizontal rules
	text = horizontalRuleRegex.ReplaceAllString(text, "")

	// Remove headers, blockquotes, bullets (e.g., ### Heading, > Quote, - Item)
	text = headerBulletRegex.ReplaceAllString(text, "")

	// Normalize extra spaces
	text = extraSpacesRegex.ReplaceAllString(text, " ")

	// Trim leading/trailing whitespace
	return strings.TrimSpace(text)
}
