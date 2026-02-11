package ui

import (
	"fmt"
	"sync"
	"time"
)

var (
	spinnerChan chan bool
	spinnerMu   sync.Mutex
)

func StartSpinner(msg string) {
	StartSpinnerWithColor(msg, Colors.Normal)
}

func StartSpinnerWithColor(msg string, c ColorFn) {
	if c == nil {
		c = Colors.Normal
	}

	style := `⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏`
	frames := []rune(style)
	length := len(frames)

	spinnerMu.Lock()

	// If a previous spinner exists, stop it cleanly before starting a new one
	if spinnerChan != nil {
		close(spinnerChan)
		spinnerChan = nil
	}
	spinnerChan = make(chan bool)
	spinnerMu.Unlock()

	ticker := time.NewTicker(100 * time.Millisecond)
	go func() {
		pos := 0

		for {
			select {
			case <-spinnerChan:
				ticker.Stop()
				return
			case <-ticker.C:
				fmt.Printf("\r%s ... %s", c("PMG: "+msg), string(frames[pos%length]))
				pos += 1
			}
		}
	}()
}

func StopSpinner() {
	spinnerMu.Lock()
	defer spinnerMu.Unlock()

	if spinnerChan == nil {
		return
	}

	// Gracefully handle the case where the spinner is already stopped
	// and the channel is closed, yet client code calls StopSpinner() again.
	defer func() {
		_ = recover()
	}()

	close(spinnerChan)

	spinnerChan = nil

	fmt.Printf("\r")
	fmt.Println()
}
