package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
)

func TestConflictModel_Navigation(t *testing.T) {
	info := ConflictInfo{
		EntryID:         "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Hostname:        "server.local",
		ExpectedVersion: "1",
		ActualVersion:   "3",
	}

	m := newConflictModel(info)
	assert.Equal(t, 0, m.cursor)

	// Move down
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
	m = updated.(conflictModel)
	assert.Equal(t, 1, m.cursor)

	// Move down again
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
	m = updated.(conflictModel)
	assert.Equal(t, 2, m.cursor)

	// Can't go past end
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
	m = updated.(conflictModel)
	assert.Equal(t, 2, m.cursor)

	// Move up
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("k")})
	m = updated.(conflictModel)
	assert.Equal(t, 1, m.cursor)
}

func TestConflictModel_SelectRetry(t *testing.T) {
	m := newConflictModel(ConflictInfo{ActualVersion: "5"})
	// Cursor starts at 0 (Retry)
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(conflictModel)

	assert.True(t, m.quitting)
	assert.Equal(t, ConflictRetry, m.chosen)
	assert.NotNil(t, cmd) // tea.Quit
}

func TestConflictModel_SelectSkip(t *testing.T) {
	m := newConflictModel(ConflictInfo{})
	// Move to "Skip"
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
	m = updated.(conflictModel)
	// Select
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(conflictModel)

	assert.Equal(t, ConflictSkip, m.chosen)
}

func TestConflictModel_EscAborts(t *testing.T) {
	m := newConflictModel(ConflictInfo{})
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updated.(conflictModel)

	assert.True(t, m.quitting)
	assert.Equal(t, ConflictAbort, m.chosen)
}

func TestConflictModel_ViewShowsInfo(t *testing.T) {
	info := ConflictInfo{
		EntryID:         "ABC123",
		Hostname:        "db.local",
		ExpectedVersion: "2",
		ActualVersion:   "4",
		Changes:         []string{"IP: 10.0.0.1 → 10.0.0.2"},
	}

	m := newConflictModel(info)
	view := m.View()

	assert.Contains(t, view, "Version Conflict")
	assert.Contains(t, view, "db.local")
	assert.Contains(t, view, "ABC123")
	assert.Contains(t, view, "Retry with current version")
	assert.Contains(t, view, "10.0.0.1")
}

func TestConflictModel_QuitReturnsEmpty(t *testing.T) {
	m := newConflictModel(ConflictInfo{})
	m.quitting = true
	assert.Empty(t, m.View())
}
