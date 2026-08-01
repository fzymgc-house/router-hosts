// Package template renders host data through a caller-supplied text/template
// (TMPL-01, TMPL-02, TMPL-03). Rendering happens entirely client-side (D-01):
// this package never runs on the server, and the server never executes
// caller-supplied template text.
package template

import (
	"bytes"
	texttemplate "text/template"
	"time"

	"github.com/samber/oops"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
)

// Entry is the per-host-entry field set exposed to a template (D-04). Every
// field is a named struct field holding a scalar or a slice of scalars —
// keyed-collection types are forbidden in this contract because
// missingkey=error is the only guard for them, and it does not catch a typo
// inside a map access.
type Entry struct {
	IPAddress string
	Hostname  string
	Aliases   []string
	Tags      []string
	Comment   string
}

// Data is the top-level value a template executes against (D-03). It is a
// struct, never a bare slice, so that adding a metadata field later never
// silently changes what an existing template's "." means.
type Data struct {
	Entries         []Entry
	Count           int
	GeneratedAt     time.Time
	ContractVersion string
	// ChangeID is a LOWER BOUND on the state Entries reflects (D-18, D-19;
	// review H1): the entries may include a mutation that landed after this
	// ID was read, never the reverse. See internal/server/watch.go for the
	// derivation-ordering rationale.
	ChangeID string
}

// Parse parses src as a template named name, using missingkey=error so a
// template referencing a field that does not exist on Entry or Data fails
// loudly (TMPL-03) instead of rendering empty. missingkey=error is
// defense-in-depth only for THIS contract because it is entirely
// struct-typed (no map value is ever the top-level or per-entry value); the
// struct typing itself is what makes an undefined field a compile-time-like
// parse/execute error rather than a silent miss.
func Parse(name, src string) (*texttemplate.Template, error) {
	tmpl, err := texttemplate.New(name).Option("missingkey=error").Parse(src)
	if err != nil {
		return nil, oops.Wrapf(err, "parse template")
	}
	return tmpl, nil
}

// Render executes tmpl against data and returns the rendered bytes. It never
// writes to a destination file (D-12): the caller is responsible for taking
// the returned bytes and writing them atomically.
func Render(tmpl *texttemplate.Template, data Data) ([]byte, error) {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, oops.Wrapf(err, "execute template")
	}
	return buf.Bytes(), nil
}

// FromProto maps a WatchHosts response's host entries plus its snapshot
// terminator into a Data value ready to render.
func FromProto(entries []*hostsv1.HostEntry, complete *hostsv1.SnapshotComplete) Data {
	out := make([]Entry, len(entries))
	for i, e := range entries {
		out[i] = Entry{
			IPAddress: e.GetIpAddress(),
			Hostname:  e.GetHostname(),
			Aliases:   e.GetAliases(),
			Tags:      e.GetTags(),
			Comment:   e.GetComment(),
		}
	}
	return Data{
		Entries:         out,
		Count:           int(complete.GetCount()),
		GeneratedAt:     complete.GetGeneratedAt().AsTime(),
		ContractVersion: complete.GetContractVersion(),
		ChangeID:        complete.GetChangeId(),
	}
}
