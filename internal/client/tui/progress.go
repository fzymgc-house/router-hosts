package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ImportStats holds streaming import counters updated from gRPC responses.
type ImportStats struct {
	Processed        int32
	Created          int32
	Updated          int32
	Skipped          int32
	Failed           int32
	Total            int32 // Expected total entries (0 if unknown)
	ValidationErrors []string
	Error            string
	Done             bool
}

// ImportStatsMsg is sent to the TUI when new stats arrive from the stream.
type ImportStatsMsg ImportStats

// progressModel is the Bubble Tea model for import progress display.
type progressModel struct {
	stats    ImportStats
	bar      progress.Model
	quitting bool
	width    int
}

var (
	statsLabelStyle = lipgloss.NewStyle().
			Bold(true).
			Width(10)

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("9"))

	successStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("2"))
)

// NewProgressModel creates a new import progress TUI model.
func NewProgressModel() progressModel {
	bar := progress.New(
		progress.WithDefaultGradient(),
		progress.WithWidth(40),
	)
	return progressModel{
		bar:   bar,
		width: 80,
	}
}

// Init implements tea.Model.
func (m progressModel) Init() tea.Cmd {
	return nil
}

// Update implements tea.Model.
func (m progressModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.bar.Width = msg.Width - 10
		if m.bar.Width > 80 {
			m.bar.Width = 80
		}
		return m, nil

	case ImportStatsMsg:
		m.stats = ImportStats(msg)
		if m.stats.Done {
			m.quitting = true
			return m, tea.Quit
		}
		return m, nil

	case progress.FrameMsg:
		barModel, cmd := m.bar.Update(msg)
		m.bar = barModel.(progress.Model)
		return m, cmd

	case tea.KeyMsg:
		if msg.String() == "q" || msg.String() == "ctrl+c" {
			m.quitting = true
			return m, tea.Quit
		}
	}
	return m, nil
}

// View implements tea.Model.
func (m progressModel) View() string {
	if m.quitting && m.stats.Done {
		return m.renderFinal()
	}

	var b strings.Builder

	b.WriteString(lipgloss.NewStyle().Bold(true).Render("Importing hosts..."))
	b.WriteString("\n\n")

	// Progress bar
	var pct float64
	if m.stats.Total > 0 {
		pct = float64(m.stats.Processed) / float64(m.stats.Total)
	} else if m.stats.Processed > 0 {
		pct = 0.5 // indeterminate
	}
	b.WriteString(m.bar.ViewAs(pct))
	b.WriteString("\n\n")

	// Counters
	b.WriteString(m.renderCounters())

	// Recent validation errors (last 5)
	if len(m.stats.ValidationErrors) > 0 {
		b.WriteString("\n" + errorStyle.Render("Validation errors:") + "\n")
		start := 0
		if len(m.stats.ValidationErrors) > 5 {
			start = len(m.stats.ValidationErrors) - 5
			fmt.Fprintf(&b, "  ... and %d more\n", start)
		}
		for _, ve := range m.stats.ValidationErrors[start:] {
			b.WriteString("  " + ve + "\n")
		}
	}

	b.WriteString("\n(q to abort)\n")
	return b.String()
}

func (m progressModel) renderCounters() string {
	var b strings.Builder
	b.WriteString(statsLabelStyle.Render("Processed:") + fmt.Sprintf(" %d", m.stats.Processed))
	if m.stats.Total > 0 {
		fmt.Fprintf(&b, "/%d", m.stats.Total)
	}
	b.WriteString("\n")
	b.WriteString(statsLabelStyle.Render("Created:") + successStyle.Render(fmt.Sprintf(" %d", m.stats.Created)) + "\n")
	if m.stats.Updated > 0 {
		b.WriteString(statsLabelStyle.Render("Updated:") + fmt.Sprintf(" %d", m.stats.Updated) + "\n")
	}
	if m.stats.Skipped > 0 {
		b.WriteString(statsLabelStyle.Render("Skipped:") + fmt.Sprintf(" %d", m.stats.Skipped) + "\n")
	}
	if m.stats.Failed > 0 {
		b.WriteString(statsLabelStyle.Render("Failed:") + errorStyle.Render(fmt.Sprintf(" %d", m.stats.Failed)) + "\n")
	}
	return b.String()
}

func (m progressModel) renderFinal() string {
	var b strings.Builder

	b.WriteString(lipgloss.NewStyle().Bold(true).Render("Import complete"))
	b.WriteString("\n\n")
	b.WriteString(m.renderCounters())

	if m.stats.Error != "" {
		b.WriteString("\n" + errorStyle.Render("Error: "+m.stats.Error) + "\n")
	}
	if len(m.stats.ValidationErrors) > 0 {
		fmt.Fprintf(&b, "\n%d validation error(s)\n", len(m.stats.ValidationErrors))
	}

	b.WriteString("\n")
	return b.String()
}
