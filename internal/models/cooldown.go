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
}
