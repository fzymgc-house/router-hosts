package template

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
)

// TestTemplate_Golden captures byte-exact output for the client-side
// consumer-template rendering path (D-14, LAZY-04), against the CURRENT
// (pre-change) production code. Data is built via FromProto from a fixed
// []*hostsv1.HostEntry plus a fixed SnapshotComplete, so there is no
// GeneratedAt volatility to strip — the timestamp is a Data.GeneratedAt
// value under this test's own control, not time.Now().
func TestTemplate_Golden(t *testing.T) {
	const src = `{{define "contract_version"}}1{{end}}` +
		`Snapshot: {{.Count}} entries, generated {{.GeneratedAt.Format "2006-01-02T15:04:05Z"}}, change {{.ChangeID}}
{{range .Entries}}{{.IPAddress}}	{{.Hostname}}{{range .Aliases}} {{.}}{{end}}{{if .Comment}}	# {{ sanitize .Comment }}{{end}}{{if .Tags}} [{{range $i, $t := .Tags}}{{if $i}}, {{end}}{{$t}}{{end}}]{{end}}
{{end}}`

	tmpl, err := Parse("golden", src)
	require.NoError(t, err)

	fixedTime := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)

	t.Run("multiple entries with a newline-bearing comment", func(t *testing.T) {
		protoEntries := []*hostsv1.HostEntry{
			{
				Id:        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
				IpAddress: "10.0.0.5",
				Hostname:  "api.fzymgc.house",
				Comment:   strPtr("role=api\nlocal-zone: evil. static"),
				Tags:      []string{"prod", "edge"},
				Aliases:   []string{"svc.fzymgc.house"},
			},
			{
				Id:        "01ARZ3NDEKTSV4RRFFQ69G5FB0",
				IpAddress: "10.0.0.9",
				Hostname:  "db.fzymgc.house",
				Aliases:   []string{"sql.fzymgc.house"},
			},
		}
		complete := &hostsv1.SnapshotComplete{
			Count:           2,
			GeneratedAt:     timestamppb.New(fixedTime),
			ContractVersion: "1",
			ChangeId:        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		}

		data := FromProto(protoEntries, complete)
		out, err := Render(tmpl, data)
		require.NoError(t, err)

		// The `sanitize` FuncMap binding collapses the comment's embedded
		// newline to a space, so the would-be injected directive stays on
		// the same rendered line as the comment text.
		want := "Snapshot: 2 entries, generated 2026-08-03T12:00:00Z, change 01ARZ3NDEKTSV4RRFFQ69G5FAV\n" +
			"10.0.0.5\tapi.fzymgc.house svc.fzymgc.house\t# role=api local-zone: evil. static [prod, edge]\n" +
			"10.0.0.9\tdb.fzymgc.house sql.fzymgc.house\n"

		require.Equal(t, want, string(out))
	})

	t.Run("empty entry set", func(t *testing.T) {
		complete := &hostsv1.SnapshotComplete{
			Count:           0,
			GeneratedAt:     timestamppb.New(fixedTime),
			ContractVersion: "1",
			ChangeId:        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		}

		data := FromProto(nil, complete)
		out, err := Render(tmpl, data)
		require.NoError(t, err)

		want := "Snapshot: 0 entries, generated 2026-08-03T12:00:00Z, change 01ARZ3NDEKTSV4RRFFQ69G5FAV\n"

		require.Equal(t, want, string(out))
	})
}

func strPtr(s string) *string { return &s }
