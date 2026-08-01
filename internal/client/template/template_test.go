package template

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fzymgc-house/router-hosts/internal/sanitize"
)

const testContractVersion = `{{define "contract_version"}}1{{end}}`

func TestTemplateRender_HappyPath(t *testing.T) {
	tmpl, err := Parse("t", testContractVersion+`{{range .Entries}}{{.IPAddress}} {{.Hostname}}{{"\n"}}{{end}}`)
	require.NoError(t, err)

	data := Data{
		Entries: []Entry{
			{
				IPAddress: "192.168.1.10",
				Hostname:  "server.local",
				Aliases:   []string{"srv.local"},
				Tags:      []string{"web"},
				Comment:   "test",
			},
		},
		Count: 1,
	}

	out, err := Render(tmpl, data)
	require.NoError(t, err)
	assert.Equal(t, "192.168.1.10 server.local\n", string(out))
}

func TestTemplateRender_CountAndGeneratedAt(t *testing.T) {
	tmpl, err := Parse("t", testContractVersion+`{{.Count}}`)
	require.NoError(t, err)

	data := Data{
		Entries: []Entry{
			{IPAddress: "192.168.1.10", Hostname: "server.local"},
		},
		Count:       1,
		GeneratedAt: time.Now().UTC(),
	}

	out, err := Render(tmpl, data)
	require.NoError(t, err)
	assert.Equal(t, "1", string(out))
}

func TestTemplateRender_ChangeIDIsRenderable(t *testing.T) {
	tmpl, err := Parse("t", testContractVersion+`{{.ChangeID}}`)
	require.NoError(t, err)

	data := Data{ChangeID: "01ARZ3NDEKTSV4RRFFQ69G5FAV"}

	out, err := Render(tmpl, data)
	require.NoError(t, err)
	assert.Equal(t, "01ARZ3NDEKTSV4RRFFQ69G5FAV", string(out))
}

func TestTemplateRender_UndefinedFieldFails(t *testing.T) {
	tmpl, err := Parse("t", testContractVersion+`{{.NoSuchField}}`)
	require.NoError(t, err)

	data := Data{Count: 1}

	out, err := Render(tmpl, data)
	require.Error(t, err)
	assert.Nil(t, out)
}

func TestTemplateVersion_DeclaredFromNamedBlock(t *testing.T) {
	tmpl, err := Parse("t", `{{define "contract_version"}} 1 {{end}}rest`)
	require.NoError(t, err)

	declared, err := DeclaredVersion(tmpl)
	require.NoError(t, err)
	assert.Equal(t, "1", declared)
}

func TestTemplateVersion_MissingBlockFails(t *testing.T) {
	tmpl, err := Parse("t", `no version block here`)
	require.NoError(t, err)

	_, err = DeclaredVersion(tmpl)
	require.Error(t, err)
	assert.Contains(t, err.Error(), ContractVersionBlockName)
}

func TestTemplateVersion_ExactMatchOnly(t *testing.T) {
	tests := []struct {
		name     string
		declared string
		served   string
		wantErr  bool
	}{
		{name: "exact match", declared: "1", served: "1", wantErr: false},
		{name: "differing versions", declared: "1", served: "2", wantErr: true},
		{name: "dotted variant is not adjacent", declared: "1.0", served: "1", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := RequireVersion(tc.declared, tc.served)
			if !tc.wantErr {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.declared)
			assert.Contains(t, err.Error(), tc.served)
		})
	}
}

func TestTemplateFuncs_SanitizeCollapsesNewline(t *testing.T) {
	tmpl, err := Parse("t", testContractVersion+`{{range .Entries}}{{ sanitize .Comment }}{{end}}`)
	require.NoError(t, err)

	data := Data{Entries: []Entry{{Comment: "line one\nlocal-zone: evil. static"}}}

	out, err := Render(tmpl, data)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "\n")
}

func TestTemplateFuncs_RawFieldStillCarriesNewline(t *testing.T) {
	tmpl, err := Parse("t", testContractVersion+`{{range .Entries}}{{ .Comment }}{{end}}`)
	require.NoError(t, err)

	data := Data{Entries: []Entry{{Comment: "line one\nlocal-zone: evil. static"}}}

	out, err := Render(tmpl, data)
	require.NoError(t, err)
	assert.Contains(t, string(out), "\n")
}

func TestTemplateFuncs_UnknownFuncFailsParse(t *testing.T) {
	_, err := Parse("t", testContractVersion+`{{ notAFunction .Comment }}`)
	require.Error(t, err)
}

func TestSanitizeParity_ServerAndTemplateAgree(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "LF", input: "line one\nline two"},
		{name: "CR", input: "line one\rline two"},
		{name: "CRLF", input: "line one\r\nline two"},
		{name: "multi-byte UTF-8", input: "héllo wörld — 日本語"},
		{name: "no line breaks", input: "plain text, nothing special"},
		{
			name: "Unicode line separator U+2028 is untouched",
			// This sanitizer collapses the two bytes that terminate a line
			// in the resolver config formats (\n, \r); it deliberately does
			// not perform Unicode-aware line-break normalisation, so U+2028
			// passes through unchanged.
			input: "line one line two",
		},
	}

	tmpl, err := Parse("t", testContractVersion+`{{ sanitize . }}`)
	require.NoError(t, err)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			direct := sanitize.CommentField(tc.input)

			var buf bytes.Buffer
			require.NoError(t, tmpl.Execute(&buf, tc.input))

			assert.Equal(t, direct, buf.String())
		})
	}
}
