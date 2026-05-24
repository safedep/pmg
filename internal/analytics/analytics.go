package analytics

import (
	"os"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/posthog/posthog-go"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
)

const (
	postHogApiKey        = "phc_3Jcw7Wytp519dM5Csf9qXiTv9J2xs8wnhGyFR9XRQrh" // gitleaks:allow
	postHogEventEndpoint = "https://us.i.posthog.com"

	telemetryDisableEnvKey = "PMG_DISABLE_TELEMETRY"

	analyticsFlushInterval = 2 * time.Second
)

var (
	globalPosthogClient posthog.Client

	// This is the distinct ID to anonymously identify an invocation of the CLI.
	globalDistinctId string
)

func init() {
	if isTelemetryDisabled() {
		return
	}

	// Telemetry is best-effort. Any failure here must degrade gracefully and
	// never abort the actual command (e.g. a package manager install).
	// Generate the distinct ID before creating the client so a UUID failure
	// does not leak the client's background flush goroutine.
	randomUUID, err := uuid.NewRandom()
	if err != nil {
		log.Warnf("failed to generate telemetry id, disabling telemetry: %v", err)
		return
	}

	client, err := posthog.NewWithConfig(postHogApiKey, posthog.Config{
		Endpoint: postHogEventEndpoint,
		Interval: analyticsFlushInterval,
		Logger:   quietPosthogLogger{},
	})
	if err != nil {
		log.Warnf("failed to initialize posthog client, disabling telemetry: %v", err)
		return
	}

	globalPosthogClient = client
	globalDistinctId = randomUUID.String()
}

// quietPosthogLogger routes posthog-go's background logs through the dry logger
// at debug level. Left unset, posthog defaults to a logger that writes INFO and
// ERROR lines to os.Stderr from its flush goroutine, which surfaces as noisy
// (and sometimes "bad file descriptor") output during package manager
// execution. Telemetry is best-effort, so we keep it quiet by default while
// still preserving the logs at debug verbosity.
type quietPosthogLogger struct{}

var _ posthog.Logger = quietPosthogLogger{}

func (quietPosthogLogger) Debugf(format string, args ...any) { log.Debugf(format, args...) }
func (quietPosthogLogger) Logf(format string, args ...any)   { log.Debugf(format, args...) }
func (quietPosthogLogger) Warnf(format string, args ...any)  { log.Debugf(format, args...) }
func (quietPosthogLogger) Errorf(format string, args ...any) { log.Debugf(format, args...) }

func isTelemetryDisabled() bool {
	if config.Get().Config.DisableTelemetry {
		return true
	}

	val := os.Getenv(telemetryDisableEnvKey)
	if booleanVal, err := strconv.ParseBool(val); err == nil {
		return booleanVal
	}

	return false
}

func IsDisabled() bool {
	return isTelemetryDisabled()
}

// We want to ensure that we do not collect any telemetry if the user has disabled them.
func Track(distinctId string, event string, properties posthog.Properties) {
	if isTelemetryDisabled() {
		return
	}

	if globalPosthogClient == nil {
		return
	}

	_ = globalPosthogClient.Enqueue(&posthog.Capture{
		DistinctId: distinctId,
		Event:      event,
		Properties: properties,
		Timestamp:  time.Now(),
	})
}

func TrackEvent(event string) {
	Track(globalDistinctId, event,
		posthog.NewProperties().
			Set("$process_person_profile", false))
}

func Close() {
	if globalPosthogClient == nil {
		return
	}

	_ = globalPosthogClient.Close()
	globalPosthogClient = nil
}
