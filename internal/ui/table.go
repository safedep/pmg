package ui

import (
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

var ansiEscapeRe = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

func VisibleWidth(s string) int {
	return utf8.RuneCountInString(ansiEscapeRe.ReplaceAllString(s, ""))
}

func RenderTable(out io.Writer, rows [][]string, after func(rowIdx int) error) error {
	if len(rows) == 0 {
		return nil
	}
	cols := len(rows[0])
	widths := make([]int, cols)
	for _, row := range rows {
		for i, cell := range row {
			if w := VisibleWidth(cell); w > widths[i] {
				widths[i] = w
			}
		}
	}
	for rIdx, row := range rows {
		for i, cell := range row {
			if i == cols-1 {
				if _, err := fmt.Fprint(out, cell); err != nil {
					return err
				}
				continue
			}
			pad := widths[i] - VisibleWidth(cell)
			if _, err := fmt.Fprint(out, cell, strings.Repeat(" ", pad+2)); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(out); err != nil {
			return err
		}
		if after != nil {
			dataIdx := rIdx - 1
			if err := after(dataIdx); err != nil {
				return err
			}
		}
	}
	return nil
}

func FirstColumnIndent(rows [][]string) string {
	if len(rows) == 0 {
		return ""
	}
	w := 0
	for _, row := range rows {
		if v := VisibleWidth(row[0]); v > w {
			w = v
		}
	}
	return strings.Repeat(" ", w+2)
}

func Truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	if n <= 3 {
		return string(runes[:n])
	}
	return string(runes[:n-3]) + "..."
}

func TruncateLeft(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	if n <= 3 {
		return string(runes[len(runes)-n:])
	}
	return "..." + string(runes[len(runes)-(n-3):])
}
