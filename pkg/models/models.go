package models

import "fmt"

type PackageAnalysisItem struct {
	Name    string
	Version string
}

func (p PackageAnalysisItem) Id() string {
	return fmt.Sprintf("%s@%s", p.Name, p.Version)
}
