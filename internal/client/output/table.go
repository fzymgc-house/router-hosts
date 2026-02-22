package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/lipgloss"
	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
)

var (
	// headerStyle styles the table header row.
	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("12")). // bright blue
			BorderBottom(true).
			BorderStyle(lipgloss.NormalBorder())

	// cellStyle styles normal table cells.
	cellStyle = lipgloss.NewStyle().
			PaddingRight(1)

	// emptyStyle styles the "no results" message.
	emptyStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("8")). // grey
			Italic(true)
)

func renderTable(w io.Writer, entries []*hostsv1.HostEntry) error {
	if len(entries) == 0 {
		_, _ = fmt.Fprintln(w, emptyStyle.Render("No host entries found."))
		return nil
	}

	columns := []table.Column{
		{Title: "ID", Width: 28},
		{Title: "IP", Width: 16},
		{Title: "HOSTNAME", Width: 30},
		{Title: "ALIASES", Width: 24},
		{Title: "TAGS", Width: 20},
		{Title: "VERSION", Width: 10},
	}

	rows := make([]table.Row, 0, len(entries))
	for _, e := range entries {
		aliases := strings.Join(e.GetAliases(), ", ")
		tags := strings.Join(e.GetTags(), ", ")
		rows = append(rows, table.Row{
			e.GetId(),
			e.GetIpAddress(),
			e.GetHostname(),
			aliases,
			tags,
			truncateVersion(e.GetVersion()),
		})
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithHeight(len(rows)+1),
	)

	s := table.DefaultStyles()
	s.Header = headerStyle
	s.Cell = cellStyle
	t.SetStyles(s)

	_, _ = fmt.Fprintln(w, t.View())
	return nil
}

func renderSnapshotsTable(w io.Writer, snapshots []*hostsv1.Snapshot) error {
	if len(snapshots) == 0 {
		_, _ = fmt.Fprintln(w, emptyStyle.Render("No snapshots found."))
		return nil
	}

	columns := []table.Column{
		{Title: "ID", Width: 28},
		{Title: "NAME", Width: 24},
		{Title: "TRIGGER", Width: 14},
		{Title: "ENTRIES", Width: 8},
		{Title: "CREATED", Width: 20},
	}

	rows := make([]table.Row, 0, len(snapshots))
	for _, s := range snapshots {
		created := ""
		if s.GetCreatedAt() != nil {
			created = s.GetCreatedAt().AsTime().Format("2006-01-02 15:04:05")
		}
		rows = append(rows, table.Row{
			s.GetSnapshotId(),
			s.GetName(),
			s.GetTrigger(),
			formatInt32(s.GetEntryCount()),
			created,
		})
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithHeight(len(rows)+1),
	)

	s := table.DefaultStyles()
	s.Header = headerStyle
	s.Cell = cellStyle
	t.SetStyles(s)

	_, _ = fmt.Fprintln(w, t.View())
	return nil
}

func formatInt32(n int32) string {
	return fmt.Sprintf("%d", n)
}

// truncateVersion returns the first 8 chars of a version string for display.
func truncateVersion(v string) string {
	if len(v) > 8 {
		return v[:8]
	}
	return v
}
