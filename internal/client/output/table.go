package output

import (
	"fmt"
	"io"
	"strings"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
)

func renderTable(w io.Writer, entries []*hostsv1.HostEntry) error {
	if len(entries) == 0 {
		fmt.Fprintln(w, "No host entries found.")
		return nil
	}

	// Simple aligned table placeholder — Task 26 replaces with Lip Gloss styling
	header := fmt.Sprintf("%-28s  %-15s  %-30s  %-20s  %s", "ID", "IP", "HOSTNAME", "ALIASES", "TAGS")
	fmt.Fprintln(w, header)
	fmt.Fprintln(w, strings.Repeat("-", len(header)))

	for _, e := range entries {
		aliases := strings.Join(e.GetAliases(), ", ")
		tags := strings.Join(e.GetTags(), ", ")
		fmt.Fprintf(w, "%-28s  %-15s  %-30s  %-20s  %s\n",
			e.GetId(), e.GetIpAddress(), e.GetHostname(), aliases, tags)
	}
	return nil
}

func renderSnapshotsTable(w io.Writer, snapshots []*hostsv1.Snapshot) error {
	if len(snapshots) == 0 {
		fmt.Fprintln(w, "No snapshots found.")
		return nil
	}

	header := fmt.Sprintf("%-28s  %-20s  %-15s  %-8s  %s", "ID", "NAME", "TRIGGER", "ENTRIES", "CREATED")
	fmt.Fprintln(w, header)
	fmt.Fprintln(w, strings.Repeat("-", len(header)))

	for _, s := range snapshots {
		created := ""
		if s.GetCreatedAt() != nil {
			created = s.GetCreatedAt().AsTime().Format("2006-01-02 15:04:05")
		}
		fmt.Fprintf(w, "%-28s  %-20s  %-15s  %-8s  %s\n",
			s.GetSnapshotId(), s.GetName(), s.GetTrigger(),
			formatInt32(s.GetEntryCount()), created)
	}
	return nil
}

func formatInt32(n int32) string {
	return fmt.Sprintf("%d", n)
}
