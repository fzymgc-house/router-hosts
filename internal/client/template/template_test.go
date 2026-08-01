package template

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTemplateRender_HappyPath(t *testing.T) {
	tmpl, err := Parse("t", `{{range .Entries}}{{.IPAddress}} {{.Hostname}}{{"\n"}}{{end}}`)
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
	tmpl, err := Parse("t", `{{.Count}}`)
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
	tmpl, err := Parse("t", `{{.ChangeID}}`)
	require.NoError(t, err)

	data := Data{ChangeID: "01ARZ3NDEKTSV4RRFFQ69G5FAV"}

	out, err := Render(tmpl, data)
	require.NoError(t, err)
	assert.Equal(t, "01ARZ3NDEKTSV4RRFFQ69G5FAV", string(out))
}

func TestTemplateRender_UndefinedFieldFails(t *testing.T) {
	tmpl, err := Parse("t", `{{.NoSuchField}}`)
	require.NoError(t, err)

	data := Data{Count: 1}

	out, err := Render(tmpl, data)
	require.Error(t, err)
	assert.Nil(t, out)
}
