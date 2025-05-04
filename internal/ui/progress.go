package ui

import (
	"os"
	"time"

	"github.com/jedib0t/go-pretty/v6/progress"
)

// ProgressTracker defines the interface for tracking progress
type ProgressTracker interface {
	Increment(count int64)
	SetValue(count int64)
	UpdateTotal(count int64)
	MarkAsDone()
	GetValue() int64
	GetTotal() int64
}

// progressTrackerImpl implements ProgressTracker using go-pretty/progress
type progressTrackerImpl struct {
	tracker *progress.Tracker
}

func (p *progressTrackerImpl) Increment(count int64) {
	if p.tracker != nil {
		p.tracker.Increment(count)
	}
}

func (p *progressTrackerImpl) SetValue(count int64) {
	if p.tracker != nil {
		p.tracker.SetValue(count)
	}
}

func (p *progressTrackerImpl) UpdateTotal(count int64) {
	if p.tracker != nil {
		p.tracker.UpdateTotal(count)
	}
}

func (p *progressTrackerImpl) MarkAsDone() {
	if p.tracker != nil {
		p.tracker.MarkAsDone()
	}
}

func (p *progressTrackerImpl) GetValue() int64 {
	if p.tracker != nil {
		return p.tracker.Value()
	}
	return 0
}

func (p *progressTrackerImpl) GetTotal() int64 {
	if p.tracker != nil {
		return p.tracker.Total
	}
	return 0
}

var progressWriter progress.Writer

func StartProgressWriter() {
	pw := progress.NewWriter()

	pw.SetAutoStop(false)
	pw.SetTrackerLength(25)
	pw.SetMessageLength(20)
	pw.SetSortBy(progress.SortByPercentDsc)
	pw.SetStyle(progress.StyleDefault)
	pw.SetOutputWriter(os.Stderr)
	pw.SetTrackerPosition(progress.PositionRight)
	pw.SetUpdateFrequency(time.Millisecond * 100)
	pw.Style().Colors = progress.StyleColorsExample
	pw.Style().Options.PercentFormat = "%4.1f%%"
	pw.Style().Visibility.Pinned = true
	pw.Style().Visibility.ETA = true
	pw.Style().Visibility.Value = true

	progressWriter = pw
	go progressWriter.Render()
}

func StopProgressWriter() {
	if progressWriter != nil {
		progressWriter.Stop()
		time.Sleep(1 * time.Second)
	}
}

func SetPinnedMessageOnProgressWriter(msg string) {
	if progressWriter != nil {
		progressWriter.SetPinnedMessages(msg)
	}
}

func TrackProgress(message string, total int) ProgressTracker {
	tracker := progress.Tracker{Message: message, Total: int64(total),
		Units: progress.UnitsDefault}

	if progressWriter != nil {
		progressWriter.AppendTracker(&tracker)
	}

	return &progressTrackerImpl{tracker: &tracker}
}

func MarkTrackerAsDone(i any) {
	if tracker, ok := i.(ProgressTracker); ok {
		tracker.MarkAsDone()
	}
}

func IncrementTrackerTotal(i any, count int64) {
	if tracker, ok := i.(ProgressTracker); ok {
		tracker.UpdateTotal(tracker.GetTotal() + count)
	}
}

func SetTrackerTotal(i any, count int64) {
	if tracker, ok := i.(ProgressTracker); ok {
		tracker.UpdateTotal(count)
	}
}

func IncrementProgress(i any, count int64) {
	if tracker, ok := i.(ProgressTracker); ok && (progressTrackerDelta(tracker) > count) {
		tracker.Increment(count)
	}
}

func UpdateValue(i any, count int64) {
	if tracker, ok := i.(ProgressTracker); ok {
		tracker.SetValue(count)
	}
}

func progressTrackerDelta(tracker ProgressTracker) int64 {
	return (tracker.GetTotal() - tracker.GetValue())
}
