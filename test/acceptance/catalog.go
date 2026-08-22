package acceptance

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type Tier string

const (
	TierP0 Tier = "P0"
	TierP1 Tier = "P1"
	TierP2 Tier = "P2"
)

type Guarantee struct {
	ID        string `yaml:"id"`
	Title     string `yaml:"title"`
	Surface   string `yaml:"surface"`
	Tier      Tier   `yaml:"tier"`
	Guarantee string `yaml:"guarantee"`
}

type Catalog struct {
	guarantees []Guarantee
	byID       map[string]Guarantee
}

func LoadCatalog(path string) (*Catalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}

	var gs []Guarantee
	if err := yaml.Unmarshal(data, &gs); err != nil {
		return nil, fmt.Errorf("parse catalog: %w", err)
	}

	c := &Catalog{guarantees: gs, byID: make(map[string]Guarantee, len(gs))}
	for _, g := range gs {
		if g.ID == "" {
			return nil, fmt.Errorf("catalog entry with empty id: %+v", g)
		}
		if _, dup := c.byID[g.ID]; dup {
			return nil, fmt.Errorf("duplicate catalog id: %s", g.ID)
		}
		switch g.Tier {
		case TierP0, TierP1, TierP2:
		default:
			return nil, fmt.Errorf("invalid tier %q for %s (want P0|P1|P2)", g.Tier, g.ID)
		}
		c.byID[g.ID] = g
	}
	return c, nil
}

func (c *Catalog) Has(id string) bool { _, ok := c.byID[id]; return ok }

func (c *Catalog) Get(id string) (Guarantee, bool) { g, ok := c.byID[id]; return g, ok }

func (c *Catalog) Guarantees() []Guarantee { return c.guarantees }

func (c *Catalog) IDs() []string {
	ids := make([]string, 0, len(c.byID))
	for id := range c.byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// DeriveFeatureID turns a script path relative to the scripts root into its
// feature id: drop the .txtar extension, keep "/" separators. Hyphens inside a
// segment stay literal.
func DeriveFeatureID(relPath string) string {
	return strings.TrimSuffix(filepath.ToSlash(relPath), ".txtar")
}

// DiscoverScripts returns the feature id of every .txtar under root.
func DiscoverScripts(root string) ([]string, error) {
	var ids []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".txtar") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		ids = append(ids, DeriveFeatureID(rel))
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(ids)
	return ids, nil
}
