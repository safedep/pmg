package fsutil

import "strings"

// foldCasePath folds case because NTFS compares names through an upcase table.
func foldCasePath(path string) string { return strings.ToUpper(path) }
