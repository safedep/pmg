package eventlog

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/safedep/dry/log"
)

// Read returns the events of the given types logged at or after since,
// oldest first. It reads every rotated file in dir. A line that does not
// parse is skipped with a warning, so one bad write does not hide the rest.
func Read(dir string, since time.Time, types ...string) ([]Event, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read event log directory %s: %w", dir, err)
	}

	var files []string
	for _, entry := range entries {
		if entry.IsDir() || !isLogFile(entry.Name()) {
			continue
		}
		files = append(files, filepath.Join(dir, entry.Name()))
	}
	sort.Strings(files)

	wanted := make(map[string]bool, len(types))
	for _, t := range types {
		wanted[t] = true
	}

	var events []Event
	for _, path := range files {
		fileEvents, err := readFile(path, since, wanted)
		if err != nil {
			return nil, err
		}
		events = append(events, fileEvents...)
	}
	return events, nil
}

func readFile(path string, since time.Time, wanted map[string]bool) ([]Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open event log %s: %w", path, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Warnf("close event log %s: %v", path, err)
		}
	}()

	// bufio.Reader has no line limit, unlike bufio.Scanner. One observation
	// of a long daemon run is one line, and its size is up to the writer.
	var events []Event
	reader := bufio.NewReader(f)
	for {
		line, err := reader.ReadBytes('\n')
		if event, ok := parseLine(path, line, since, wanted); ok {
			events = append(events, event)
		}
		if err == io.EOF {
			return events, nil
		}
		if err != nil {
			return nil, fmt.Errorf("read event log %s: %w", path, err)
		}
	}
}

func parseLine(path string, line []byte, since time.Time, wanted map[string]bool) (Event, bool) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return Event{}, false
	}
	var event Event
	if err := json.Unmarshal(line, &event); err != nil {
		log.Warnf("skipping an event log line in %s: %v", path, err)
		return Event{}, false
	}
	if event.Timestamp.Before(since) {
		return Event{}, false
	}
	if len(wanted) > 0 && !wanted[event.EventType] {
		return Event{}, false
	}
	return event, true
}
