package output

import (
	"io"
	"os"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
	"golang.org/x/term"
)

// DetectFormat returns "table" when stdout is a TTY, "json" otherwise.
func DetectFormat() string {
	if term.IsTerminal(int(os.Stdout.Fd())) {
		return "table"
	}
	return "json"
}

// RenderHosts outputs host entries in the specified format.
func RenderHosts(w io.Writer, format string, entries []*hostsv1.HostEntry) error {
	switch format {
	case "json":
		return renderJSON(w, entries)
	case "csv":
		return renderCSV(w, entries)
	default:
		return renderTable(w, entries)
	}
}

// RenderSnapshots outputs snapshots in the specified format.
func RenderSnapshots(w io.Writer, format string, snapshots []*hostsv1.Snapshot) error {
	switch format {
	case "json":
		return renderSnapshotsJSON(w, snapshots)
	case "csv":
		return renderSnapshotsCSV(w, snapshots)
	default:
		return renderSnapshotsTable(w, snapshots)
	}
}
