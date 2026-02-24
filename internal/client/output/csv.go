package output

import (
	"encoding/csv"
	"io"
	"strings"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
)

func renderCSV(w io.Writer, entries []*hostsv1.HostEntry) error {
	cw := csv.NewWriter(w)

	if err := cw.Write([]string{"id", "ip_address", "hostname", "aliases", "comment", "tags", "version"}); err != nil {
		return err
	}

	for _, e := range entries {
		comment := ""
		if e.Comment != nil {
			comment = *e.Comment
		}
		row := []string{
			e.GetId(),
			e.GetIpAddress(),
			e.GetHostname(),
			strings.Join(e.GetAliases(), ";"),
			comment,
			strings.Join(e.GetTags(), ";"),
			e.GetVersion(),
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func renderSnapshotsCSV(w io.Writer, snapshots []*hostsv1.Snapshot) error {
	cw := csv.NewWriter(w)

	if err := cw.Write([]string{"snapshot_id", "name", "trigger", "entry_count", "created_at"}); err != nil {
		return err
	}

	for _, s := range snapshots {
		created := ""
		if s.GetCreatedAt() != nil {
			created = s.GetCreatedAt().AsTime().String()
		}
		row := []string{
			s.GetSnapshotId(),
			s.GetName(),
			s.GetTrigger(),
			formatInt32(s.GetEntryCount()),
			created,
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}
