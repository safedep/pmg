package ui

import (
	"fmt"
	"time"
)

var spinnerChan chan bool

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

	spinnerChan = make(chan bool)

	ticker := time.NewTicker(100 * time.Millisecond)
	go func() {
		pos := 0

		for {
			select {
			case <-spinnerChan:
				ticker.Stop()
				return
			case <-ticker.C:
				fmt.Printf("\r%s ... %s", c(msg), string(frames[pos%length]))
				pos += 1
			}
		}
	}()
}

func StopSpinner() {
	// Gracefully handle the case where the spinner is already stopped
	// and the channel is closed, yet client code calls StopSpinner() again.
	defer func() {
		_ = recover()
	}()

	close(spinnerChan)

	fmt.Printf("\r")
	fmt.Println()
}
