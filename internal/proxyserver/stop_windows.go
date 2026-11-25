//go:build windows

package proxyserver

import (
	"fmt"
	"os"
	"sync"

	"github.com/safedep/dry/log"
	"golang.org/x/sys/windows"
)

func stopEventName(pid int) string {
	return fmt.Sprintf("Local\\pmg-proxy-stop-%d", pid)
}

func listenStopRequest() (<-chan struct{}, func(), error) {
	name, err := windows.UTF16PtrFromString(stopEventName(os.Getpid()))
	if err != nil {
		return nil, nil, fmt.Errorf("encode stop event name: %w", err)
	}
	handle, err := windows.CreateEvent(nil, 1, 0, name)
	if err != nil {
		if handle != 0 {
			if cerr := windows.CloseHandle(handle); cerr != nil {
				log.Warnf("close existing proxy stop event handle: %v", cerr)
			}
		}
		return nil, nil, fmt.Errorf("create stop event: %w", err)
	}

	stopCh := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer close(stopCh)
		if _, werr := windows.WaitForSingleObject(handle, windows.INFINITE); werr != nil {
			log.Warnf("wait for proxy stop event: %v", werr)
		}
	}()

	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			if serr := windows.SetEvent(handle); serr != nil {
				log.Warnf("signal proxy stop event during cleanup: %v", serr)
			}
			<-done
			if cerr := windows.CloseHandle(handle); cerr != nil {
				log.Warnf("close proxy stop event handle: %v", cerr)
			}
		})
	}

	return stopCh, cleanup, nil
}

func requestStop(pid int) error {
	name, err := windows.UTF16PtrFromString(stopEventName(pid))
	if err != nil {
		return fmt.Errorf("encode stop event name: %w", err)
	}
	handle, err := windows.OpenEvent(windows.EVENT_MODIFY_STATE, false, name)
	if err != nil {
		return fmt.Errorf("open stop event for proxy (pid %d): %w", pid, err)
	}
	defer func() {
		if cerr := windows.CloseHandle(handle); cerr != nil {
			log.Warnf("close stop event handle for proxy (pid %d): %v", pid, cerr)
		}
	}()
	if err := windows.SetEvent(handle); err != nil {
		return fmt.Errorf("signal proxy (pid %d): %w", pid, err)
	}
	return nil
}
