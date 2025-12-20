package eventlog

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// EventType represents the type of event being logged
type EventType string

const (
	EventTypeMalwareBlocked    EventType = "malware_blocked"
	EventTypeMalwareConfirmed  EventType = "malware_confirmed"
	EventTypeInstallAllowed    EventType = "install_allowed"
	EventTypeInstallStarted    EventType = "install_started"
	EventTypeDependencyResolved EventType = "dependency_resolved"
	EventTypeError             EventType = "error"
)

// Event represents a security event
type Event struct {
	Timestamp   time.Time              `json:"timestamp"`
	EventType   EventType              `json:"event_type"`
	Message     string                 `json:"message"`
	PackageName string                 `json:"package_name,omitempty"`
	Version     string                 `json:"version,omitempty"`
	Ecosystem   string                 `json:"ecosystem,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// Logger represents an event logger
type Logger struct {
	file   *os.File
	writer io.Writer
	mu     sync.Mutex
	active bool
}

var (
	globalLogger *Logger
	once         sync.Once
)

// GetDefaultLogDir returns the default log directory based on the OS
func GetDefaultLogDir() (string, error) {
	var baseDir string

	switch runtime.GOOS {
	case "windows":
		// Windows: %LOCALAPPDATA%\pmg\logs or %USERPROFILE%\.pmg\logs
		baseDir = os.Getenv("LOCALAPPDATA")
		if baseDir == "" {
			baseDir = os.Getenv("USERPROFILE")
			if baseDir == "" {
				return "", fmt.Errorf("could not determine Windows user directory")
			}
			return filepath.Join(baseDir, ".pmg", "logs"), nil
		}
		return filepath.Join(baseDir, "pmg", "logs"), nil
	case "darwin", "linux":
		// macOS and Linux: ~/.pmg/logs
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("could not determine home directory: %w", err)
		}
		return filepath.Join(homeDir, ".pmg", "logs"), nil
	default:
		return "", fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

// Initialize sets up the global event logger with the default log directory
func Initialize() error {
	logDir, err := GetDefaultLogDir()
	if err != nil {
		return err
	}
	return InitializeWithDir(logDir)
}

// InitializeWithFile sets up the global event logger with a specific file path
func InitializeWithFile(filePath string) error {
	var initErr error
	once.Do(func() {
		globalLogger = &Logger{}
		initErr = globalLogger.initWithFile(filePath)
	})
	return initErr
}

// InitializeWithDir sets up the global event logger with a custom log directory
func InitializeWithDir(logDir string) error {
	var initErr error
	once.Do(func() {
		globalLogger = &Logger{}
		initErr = globalLogger.init(logDir)
	})
	return initErr
}

// reinitializeForTest resets and reinitializes the logger for testing purposes
// This should only be used in tests
func reinitializeForTest(logDir string) error {
	// Close existing logger if any
	if globalLogger != nil {
		globalLogger.Close()
	}
	
	// Reset once
	once = sync.Once{}
	
	// Initialize new logger
	return InitializeWithDir(logDir)
}

// init initializes the logger with the specified directory
func (l *Logger) init(logDir string) error {
	// Create log directory if it doesn't exist
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// Create log file with timestamp-based naming
	logFileName := time.Now().Format("20060102") + "-pmg.log"
	logFilePath := filepath.Join(logDir, logFileName)

	file, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	l.file = file
	l.writer = file
	l.active = true

	// Clean up old logs in background
	go l.cleanupOldLogs(logDir)

	return nil
}

// initWithFile initializes the logger with a specific file path
func (l *Logger) initWithFile(filePath string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(filePath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create log directory: %w", err)
		}
	}

	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	l.file = file
	l.writer = file
	l.active = true

	// No cleanup needed for custom log files (user manages them)

	return nil
}

// cleanupOldLogs removes log files older than 7 days
func (l *Logger) cleanupOldLogs(logDir string) {
	cutoff := time.Now().AddDate(0, 0, -7)

	entries, err := os.ReadDir(logDir)
	if err != nil {
		// Silently fail if we can't read the directory
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// Only process *-pmg.log files
		name := entry.Name()
		matched, err := filepath.Match("*-pmg.log", name)
		if err != nil || !matched {
			continue
		}

		filePath := filepath.Join(logDir, name)
		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.ModTime().Before(cutoff) {
			os.Remove(filePath)
		}
	}
}

// Log writes an event to the log file
func (l *Logger) Log(event Event) error {
	if !l.active {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Set timestamp if not already set
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Marshal event to JSON
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	// Write to file
	_, err = l.writer.Write(append(data, '\n'))
	if err != nil {
		return fmt.Errorf("failed to write event: %w", err)
	}

	// Flush to ensure data is written
	if l.file != nil {
		l.file.Sync()
	}

	return nil
}

// Close closes the logger
func (l *Logger) Close() error {
	if !l.active {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.active = false
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// Global logging functions

// LogEvent logs an event using the global logger
func LogEvent(event Event) error {
	if globalLogger == nil || !globalLogger.active {
		// If logger is not initialized or not active, silently fail
		return nil
	}
	return globalLogger.Log(event)
}

// LogMalwareBlocked logs when malware is blocked
func LogMalwareBlocked(packageName, version, ecosystem, reason string, details map[string]interface{}) {
	event := Event{
		EventType:   EventTypeMalwareBlocked,
		Message:     fmt.Sprintf("Blocked installation of malicious package: %s@%s", packageName, version),
		PackageName: packageName,
		Version:     version,
		Ecosystem:   ecosystem,
		Details:     details,
	}
	if details == nil {
		event.Details = make(map[string]interface{})
	}
	event.Details["reason"] = reason
	LogEvent(event)
}

// LogMalwareConfirmed logs when user confirms installation despite warning
func LogMalwareConfirmed(packageName, version, ecosystem string) {
	event := Event{
		EventType:   EventTypeMalwareConfirmed,
		Message:     fmt.Sprintf("User confirmed installation of flagged package: %s@%s", packageName, version),
		PackageName: packageName,
		Version:     version,
		Ecosystem:   ecosystem,
	}
	LogEvent(event)
}

// LogInstallAllowed logs when an installation is allowed
func LogInstallAllowed(packageName, version, ecosystem string, packageCount int) {
	event := Event{
		EventType:   EventTypeInstallAllowed,
		Message:     fmt.Sprintf("Installation allowed for %s@%s (%d packages analyzed)", packageName, version, packageCount),
		PackageName: packageName,
		Version:     version,
		Ecosystem:   ecosystem,
		Details: map[string]interface{}{
			"packages_analyzed": packageCount,
		},
	}
	LogEvent(event)
}

// LogInstallStarted logs when an installation starts
func LogInstallStarted(packageManager string, args []string) {
	event := Event{
		EventType: EventTypeInstallStarted,
		Message:   fmt.Sprintf("Starting package installation with %s", packageManager),
		Details: map[string]interface{}{
			"package_manager": packageManager,
			"arguments":       args,
		},
	}
	LogEvent(event)
}

// LogError logs an error event
func LogError(message string, err error) {
	event := Event{
		EventType: EventTypeError,
		Message:   message,
		Details: map[string]interface{}{
			"error": err.Error(),
		},
	}
	LogEvent(event)
}

// Close closes the global logger
func Close() error {
	if globalLogger != nil {
		return globalLogger.Close()
	}
	return nil
}

// IsInitialized returns whether the global logger is initialized
func IsInitialized() bool {
	return globalLogger != nil && globalLogger.active
}

