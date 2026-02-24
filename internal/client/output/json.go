package output

import (
	"encoding/json"
	"io"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
)

func renderJSON(w io.Writer, entries []*hostsv1.HostEntry) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(entries)
}

func renderSnapshotsJSON(w io.Writer, snapshots []*hostsv1.Snapshot) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(snapshots)
}
