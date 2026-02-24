package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
)

func TestProgressModel_UpdateStats(t *testing.T) {
	m := NewProgressModel()

	stats := ImportStatsMsg{
		Processed: 10,
		Created:   8,
		Skipped:   2,
		Total:     20,
	}

	updated, _ := m.Update(stats)
	m = updated.(progressModel)

	assert.Equal(t, int32(10), m.stats.Processed)
	assert.Equal(t, int32(8), m.stats.Created)
	assert.Equal(t, int32(2), m.stats.Skipped)
	assert.False(t, m.quitting)
}

func TestProgressModel_DoneQuitsProgram(t *testing.T) {
	m := NewProgressModel()

	stats := ImportStatsMsg{
		Processed: 20,
		Created:   20,
		Total:     20,
		Done:      true,
	}

	updated, cmd := m.Update(stats)
	m = updated.(progressModel)

	assert.True(t, m.quitting)
	assert.NotNil(t, cmd) // tea.Quit
}

func TestProgressModel_ViewShowsCounters(t *testing.T) {
	m := NewProgressModel()
	m.stats = ImportStats{
		Processed: 5,
		Created:   3,
		Failed:    2,
		Total:     10,
	}

	view := m.View()
	assert.Contains(t, view, "Importing hosts...")
	assert.Contains(t, view, "5")
	assert.Contains(t, view, "3")
}

func TestProgressModel_ViewShowsValidationErrors(t *testing.T) {
	m := NewProgressModel()
	m.stats = ImportStats{
		Processed:        2,
		Failed:           1,
		ValidationErrors: []string{"Line 3: invalid IP address"},
	}

	view := m.View()
	assert.Contains(t, view, "Validation errors")
	assert.Contains(t, view, "Line 3: invalid IP address")
}

func TestProgressModel_FinalViewOnDone(t *testing.T) {
	m := NewProgressModel()
	m.quitting = true
	m.stats = ImportStats{
		Processed: 10,
		Created:   9,
		Failed:    1,
		Done:      true,
		Error:     "partial failure",
	}

	view := m.View()
	assert.Contains(t, view, "Import complete")
	assert.Contains(t, view, "partial failure")
}

func TestProgressModel_WindowResize(t *testing.T) {
	m := NewProgressModel()

	updated, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	m = updated.(progressModel)

	assert.Equal(t, 120, m.width)
	assert.Equal(t, 80, m.bar.Width) // capped at 80
}

func TestProgressModel_QuitOnCtrlC(t *testing.T) {
	m := NewProgressModel()

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	m = updated.(progressModel)

	assert.True(t, m.quitting)
}
