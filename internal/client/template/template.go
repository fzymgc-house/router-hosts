// Package template renders host data through a caller-supplied text/template
// (TMPL-01, TMPL-02, TMPL-03). Rendering happens entirely client-side (D-01):
// this package never runs on the server, and the server never executes
// caller-supplied template text.
package template

import (
	"bytes"
	"strings"
	texttemplate "text/template"
	"time"

	"github.com/samber/oops"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
	"github.com/fzymgc-house/router-hosts/internal/sanitize"
)

// ContractVersionBlockName is the named template block every consumer
// template must declare, stating the contract version it targets (D-05).
//
//	{{define "contract_version"}}1{{end}}
//
// A template lacking this block is refused by DeclaredVersion before any
// connection to the server is opened.
const ContractVersionBlockName = "contract_version"

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

// FuncMap returns the template functions contract v1 publishes. Its key set
// is part of the contract (D-17): removing or renaming a key is a breaking
// change that bumps the contract version; adding a key is compatible and
// does not.
//
// text/template performs no escaping of any kind — that is html/template —
// so a consumer template emitting .Comment or a .Tags element into a
// resolver config must pass it through sanitize, or a value containing a
// newline breaks out of a "# ..." comment line and injects active resolver
// directives into the generated output (GH #349, router-hosts-00b.2). The
// server-side output generators reach the identical implementation through
// internal/sanitize; see internal/server/hostsfile.go's sanitizeCommentField.
func FuncMap() texttemplate.FuncMap {
	return texttemplate.FuncMap{
		"sanitize": sanitize.CommentField,
	}
}

// Parse parses src as a template named name, using missingkey=error so a
// template referencing a field that does not exist on Entry or Data fails
// loudly (TMPL-03) instead of rendering empty. missingkey=error is
// defense-in-depth only for THIS contract because it is entirely
// struct-typed (no map value is ever the top-level or per-entry value); the
// struct typing itself is what makes an undefined field a compile-time-like
// parse/execute error rather than a silent miss.
//
// FuncMap is registered via .Funcs BEFORE .Parse: text/template resolves
// function names at parse time, so a template calling an unregistered
// function fails to parse rather than failing silently at execute time.
func Parse(name, src string) (*texttemplate.Template, error) {
	unparsed := texttemplate.New(name).
		Option("missingkey=error").
		Funcs(FuncMap())
	tmpl, err := unparsed.Parse(src)
	if err != nil {
		return nil, oops.Wrapf(err, "parse template")
	}
	return tmpl, nil
}

// DeclaredVersion returns the contract version tmpl declares in its
// ContractVersionBlockName named block (D-05). A template lacking that
// block returns a non-nil error naming the block that must be declared and
// showing the exact literal a template must contain to declare version 1.
func DeclaredVersion(tmpl *texttemplate.Template) (string, error) {
	versionTmpl := tmpl.Lookup(ContractVersionBlockName)
	if versionTmpl == nil {
		return "", oops.Errorf(
			"template must declare its contract version in a %q named block, e.g. {{define %q}}1{{end}}",
			ContractVersionBlockName, ContractVersionBlockName,
		)
	}
	var buf bytes.Buffer
	if err := versionTmpl.Execute(&buf, nil); err != nil {
		return "", oops.Wrapf(err, "evaluate contract version block")
	}
	return strings.TrimSpace(buf.String()), nil
}

// RequireVersion refuses a template whose declared version does not exactly
// match served (D-05). Comparison is exact string equality — no prefix,
// range, or empty-string wildcard — so "1.0" is refused against a served
// version of "1" rather than treated as adjacent to it.
func RequireVersion(declared, served string) error {
	if declared == served {
		return nil
	}
	return oops.Errorf(
		"template targets contract version %q, but this server serves version %q; see docs/reference/template-contract.md",
		declared, served,
	)
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
