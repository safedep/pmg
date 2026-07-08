package models

// BlocklistBlock records a package blocked by the block.packages policy.
type BlocklistBlock struct {
	Name    string
	Version string
	Reason  string
}
