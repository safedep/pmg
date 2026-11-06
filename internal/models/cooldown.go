package models

import "time"

// CooldownBlock records a package blocked by the dependency cooldown policy.
type CooldownBlock struct {
	Name         string
	Version      string
	PublishDate  time.Time
	DaysAgo      int
	DaysLeft     int
	CooldownDays int

	// PolicyRevision is the revision of the cloud policy of the tenant that
	// set the cooldown. It is 0 when the local config set the cooldown.
	PolicyRevision uint64
}

// CooldownWithheldVersion is one version stripped from registry metadata by the
// dependency cooldown policy.
type CooldownWithheldVersion struct {
	Version  string
	DaysLeft int
}

// CooldownWithheld records versions stripped from a package's metadata while
// older eligible versions remained. It is a hint, not a definite block: the
// resolver may have fallen back to an eligible version, or it may have failed
// because a dependency required exactly a withheld version.
type CooldownWithheld struct {
	Name     string
	Versions []CooldownWithheldVersion
}
