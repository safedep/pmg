package models

import (
	"fmt"
)

type Package struct {
	Name    string
	Version string
}

func (p Package) Id() string {
	return fmt.Sprintf("%s@%s", p.Name, p.Version)
}

type PackageInfo struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Dependencies map[string]string `json:"dependencies"`
}

type DependencyNode struct {
	Name         string
	Version      string
	Dependencies map[string]*DependencyNode
}
