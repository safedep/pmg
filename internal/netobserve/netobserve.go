// Package netobserve reads the network observations of past runs from the
// event log, selects the runs a command asks for and folds them into one
// table of destinations.
package netobserve

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/internal/audit"
	"github.com/safedep/pmg/internal/eventlog"
	"github.com/safedep/pmg/proxy/netpolicy"
)

// Record is one network_observation event, with the time it was logged.
type Record struct {
	netpolicy.Observation
	Timestamp time.Time
}

// Read returns the observations logged at or after since, oldest first. A
// line that does not decode is skipped with a warning.
func Read(dir string, since time.Time) ([]Record, error) {
	events, err := eventlog.Read(dir, since, string(audit.EventTypeNetworkObservation))
	if err != nil {
		return nil, err
	}
	var records []Record
	for _, event := range events {
		record, err := decode(event)
		if err != nil {
			log.Warnf("skipping a network observation in the event log: %v", err)
			continue
		}
		records = append(records, record)
	}
	return records, nil
}

// decode reads the event's details back into the observation. The event
// log stores details as JSON, so a round trip through JSON gives the
// typed destinations.
func decode(event eventlog.Event) (Record, error) {
	data, err := json.Marshal(event.Details)
	if err != nil {
		return Record{}, err
	}
	var record Record
	if err := json.Unmarshal(data, &record.Observation); err != nil {
		return Record{}, err
	}
	if record.RunID == "" {
		return Record{}, errors.New("network observation without a run id")
	}
	record.Timestamp = event.Timestamp
	return record, nil
}

// Selector picks the runs of a proposal. RunID picks one run wherever it
// ran. Otherwise RepoRoot picks the runs of one repository, and Last keeps
// the newest of them.
type Selector struct {
	RunID    string
	RepoRoot string
	Last     bool
}

// Select returns the records the selector picks, oldest first.
func Select(records []Record, s Selector) []Record {
	if s.RunID != "" {
		for _, record := range records {
			if record.RunID == s.RunID {
				return []Record{record}
			}
		}
		return nil
	}

	var picked []Record
	for _, record := range records {
		if record.RepoRoot == s.RepoRoot {
			picked = append(picked, record)
		}
	}
	sort.SliceStable(picked, func(i, j int) bool { return picked[i].Timestamp.Before(picked[j].Timestamp) })
	if s.Last && len(picked) > 1 {
		picked = picked[len(picked)-1:]
	}
	return picked
}

// Merge folds the runs into one table, one row per host, port and client.
// The newest run decides a row's decision.
func Merge(records []Record) []netpolicy.Destination {
	var rows []netpolicy.Destination
	for _, record := range records {
		rows = append(rows, record.Destinations...)
	}
	return netpolicy.Fold(rows)
}

// ParseWindow reads a window such as 30d, 12h or 90m into the time it
// starts at. Go durations have no day unit, and a day is the unit people
// reason about retention in.
func ParseWindow(window string, now time.Time) (time.Time, error) {
	if strings.HasSuffix(window, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(window, "d"))
		if err != nil || days <= 0 {
			return time.Time{}, fmt.Errorf("invalid window %q", window)
		}
		return now.AddDate(0, 0, -days), nil
	}
	d, err := time.ParseDuration(window)
	if err != nil || d <= 0 {
		return time.Time{}, fmt.Errorf("invalid window %q", window)
	}
	return now.Add(-d), nil
}
