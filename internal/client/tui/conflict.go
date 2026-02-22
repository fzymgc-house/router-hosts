package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ConflictAction is the user's chosen resolution for a version conflict.
type ConflictAction int

const (
	ConflictRetry  ConflictAction = iota // Retry with the current server version
	ConflictSkip                         // Skip this update
	ConflictAbort                        // Abort the operation entirely
)

// ConflictInfo holds the details shown to the user during conflict resolution.
type ConflictInfo struct {
	EntryID         string
	Hostname        string
	ExpectedVersion string
	ActualVersion   string
	// Optional diff lines (old → new) for the user to review.
	Changes []string
}

// ConflictResult is returned after the TUI exits.
type ConflictResult struct {
	Action  ConflictAction
	Version string // The actual (current) version to retry with
}

// conflictModel is the Bubble Tea model for version conflict resolution.
type conflictModel struct {
	info     ConflictInfo
	cursor   int
	choices  []string
	quitting bool
	chosen   ConflictAction
}

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("9")) // red

	diffOldStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("1")) // red

	diffNewStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("2")) // green

	selectedStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("6")) // cyan
)

func newConflictModel(info ConflictInfo) conflictModel {
	return conflictModel{
		info:    info,
		choices: []string{"Retry with current version", "Skip this entry", "Abort"},
	}
}

func (m conflictModel) Init() tea.Cmd {
	return nil
}

func (m conflictModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.choices)-1 {
				m.cursor++
			}
		case "enter":
			m.chosen = ConflictAction(m.cursor)
			m.quitting = true
			return m, tea.Quit
		case "q", "esc":
			m.chosen = ConflictAbort
			m.quitting = true
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m conflictModel) View() string {
	if m.quitting {
		return ""
	}

	var b strings.Builder

	b.WriteString(titleStyle.Render("Version Conflict"))
	b.WriteString("\n\n")
	b.WriteString(fmt.Sprintf("Entry:    %s (%s)\n", m.info.Hostname, m.info.EntryID))
	b.WriteString(fmt.Sprintf("Expected: %s\n", diffOldStyle.Render("v"+m.info.ExpectedVersion)))
	b.WriteString(fmt.Sprintf("Actual:   %s\n", diffNewStyle.Render("v"+m.info.ActualVersion)))

	if len(m.info.Changes) > 0 {
		b.WriteString("\nChanges:\n")
		for _, line := range m.info.Changes {
			b.WriteString("  " + line + "\n")
		}
	}

	b.WriteString("\nChoose an action:\n\n")

	for i, choice := range m.choices {
		cursor := "  "
		style := lipgloss.NewStyle()
		if m.cursor == i {
			cursor = "> "
			style = selectedStyle
		}
		b.WriteString(cursor + style.Render(choice) + "\n")
	}

	b.WriteString("\n(↑/↓ to move, enter to select, q to abort)\n")

	return b.String()
}

// RunConflictResolution launches the interactive conflict resolution TUI.
// Returns the user's chosen action and the current version for retry.
func RunConflictResolution(info ConflictInfo) (ConflictResult, error) {
	m := newConflictModel(info)
	p := tea.NewProgram(m)
	final, err := p.Run()
	if err != nil {
		return ConflictResult{Action: ConflictAbort}, err
	}

	fm := final.(conflictModel)
	return ConflictResult{
		Action:  fm.chosen,
		Version: info.ActualVersion,
	}, nil
}
