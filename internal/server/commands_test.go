package server

import (
	"context"
	"log/slog"
	"testing"

	"github.com/oklog/ulid/v2"
	"github.com/samber/oops"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fzymgc-house/router-hosts/internal/domain"
	"github.com/fzymgc-house/router-hosts/internal/storage/sqlite"
)

// newTestHandler creates a CommandHandler backed by an in-memory SQLite DB.
func newTestHandler(t *testing.T) (*CommandHandler, context.Context) {
	t.Helper()
	ctx := context.Background()
	store, err := sqlite.New("file::memory:?mode=memory&cache=shared", slog.Default())
	require.NoError(t, err)
	require.NoError(t, store.Initialize(ctx))
	t.Cleanup(func() { _ = store.Close() })
	return NewCommandHandler(store), ctx
}

func strPtr(s string) *string { return &s }

// ---------- AddHost tests ----------

func TestAddHost_HappyPath(t *testing.T) {
	h, ctx := newTestHandler(t)

	entry, err := h.AddHost(ctx, "192.168.1.1", "host1.local", strPtr("my host"), []string{"web"}, []string{"alias1.local"})
	require.NoError(t, err)
	require.NotNil(t, entry)

	assert.NotEqual(t, ulid.ULID{}, entry.ID)
	assert.Equal(t, "192.168.1.1", entry.IP)
	assert.Equal(t, "host1.local", entry.Hostname)
	assert.Equal(t, "my host", *entry.Comment)
	assert.Equal(t, []string{"web"}, entry.Tags)
	assert.Equal(t, []string{"alias1.local"}, entry.Aliases)
	assert.Equal(t, "1", entry.Version)
	assert.False(t, entry.CreatedAt.IsZero())
}

func TestAddHost_DuplicateRejected(t *testing.T) {
	h, ctx := newTestHandler(t)

	_, err := h.AddHost(ctx, "192.168.1.1", "host1.local", nil, nil, nil)
	require.NoError(t, err)

	_, err = h.AddHost(ctx, "192.168.1.1", "host1.local", nil, nil, nil)
	require.Error(t, err)

	oopsErr, ok := oops.AsOops(err)
	require.True(t, ok)
	assert.Equal(t, domain.CodeDuplicate, oopsErr.Code())
}

func TestAddHost_InvalidIP(t *testing.T) {
	h, ctx := newTestHandler(t)

	_, err := h.AddHost(ctx, "not-an-ip", "host1.local", nil, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid IP address")
}

func TestAddHost_InvalidHostname(t *testing.T) {
	h, ctx := newTestHandler(t)

	_, err := h.AddHost(ctx, "192.168.1.1", "", nil, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hostname cannot be empty")
}

func TestAddHost_InvalidAlias(t *testing.T) {
	h, ctx := newTestHandler(t)

	// Alias matching hostname should fail
	_, err := h.AddHost(ctx, "192.168.1.1", "host1.local", nil, nil, []string{"host1.local"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "alias validation")
}

func TestAddHost_NilTagsAndAliases(t *testing.T) {
	h, ctx := newTestHandler(t)

	entry, err := h.AddHost(ctx, "10.0.0.1", "empty.local", nil, nil, nil)
	require.NoError(t, err)

	assert.Equal(t, []string{}, entry.Tags)
	assert.Equal(t, []string{}, entry.Aliases)
}

// ---------- UpdateHost tests ----------

func TestUpdateHost_IPChange(t *testing.T) {
	h, ctx := newTestHandler(t)

	entry, err := h.AddHost(ctx, "192.168.1.1", "host1.local", nil, nil, nil)
	require.NoError(t, err)

	newIP := "10.0.0.1"
	updated, err := h.UpdateHost(ctx, entry.ID, &newIP, nil, nil, nil, nil, entry.Version)
	require.NoError(t, err)

	assert.Equal(t, "10.0.0.1", updated.IP)
	assert.Equal(t, "2", updated.Version)
}

func TestUpdateHost_HostnameChange(t *testing.T) {
	h, ctx := newTestHandler(t)

	entry, err := h.AddHost(ctx, "192.168.1.1", "old.local", nil, nil, nil)
	require.NoError(t, err)

	newHostname := "new.local"
	updated, err := h.UpdateHost(ctx, entry.ID, nil, &newHostname, nil, nil, nil, entry.Version)
	require.NoError(t, err)

	assert.Equal(t, "new.local", updated.Hostname)
	assert.Equal(t, "2", updated.Version)
}

func TestUpdateHost_CommentChange(t *testing.T) {
	h, ctx := newTestHandler(t)

	entry, err := h.AddHost(ctx, "192.168.1.1", "host1.local", nil, nil, nil)
	require.NoError(t, err)

	newComment := strPtr("updated comment")
	updated, err := h.UpdateHost(ctx, entry.ID, nil, nil, &newComment, nil, nil, entry.Version)
	require.NoError(t, err)

	require.NotNil(t, updated.Comment)
	assert.Equal(t, "updated comment", *updated.Comment)
}

func TestUpdateHost_TagsChange(t *testing.T) {
	h, ctx := newTestHandler(t)

	entry, err := h.AddHost(ctx, "192.168.1.1", "host1.local", nil, []string{"old"}, nil)
	require.NoError(t, err)

	newTags := []string{"new", "tags"}
	updated, err := h.UpdateHost(ctx, entry.ID, nil, nil, nil, &newTags, nil, entry.Version)
	require.NoError(t, err)

	assert.Equal(t, []string{"new", "tags"}, updated.Tags)
}

func TestUpdateHost_AliasesChange(t *testing.T) {
	h, ctx := newTestHandler(t)

	entry, err := h.AddHost(ctx, "192.168.1.1", "host1.local", nil, nil, nil)
	require.NoError(t, err)

	newAliases := []string{"alias1.local", "alias2.local"}
	updated, err := h.UpdateHost(ctx, entry.ID, nil, nil, nil, nil, &newAliases, entry.Version)
	require.NoError(t, err)

	assert.Equal(t, []string{"alias1.local", "alias2.local"}, updated.Aliases)
}

func TestUpdateHost_VersionConflict(t *testing.T) {
	h, ctx := newTestHandler(t)

	entry, err := h.AddHost(ctx, "192.168.1.1", "host1.local", nil, nil, nil)
	require.NoError(t, err)

	// Use wrong version
	newIP := "10.0.0.1"
	_, err = h.UpdateHost(ctx, entry.ID, &newIP, nil, nil, nil, nil, "999")
	require.Error(t, err)

	oopsErr, ok := oops.AsOops(err)
	require.True(t, ok)
	assert.Equal(t, domain.CodeVersionConflict, oopsErr.Code())
}

func TestUpdateHost_NotFound(t *testing.T) {
	h, ctx := newTestHandler(t)

	fakeID := ulid.Make()
	newIP := "10.0.0.1"
	_, err := h.UpdateHost(ctx, fakeID, &newIP, nil, nil, nil, nil, "")
	require.Error(t, err)

	oopsErr, ok := oops.AsOops(err)
	require.True(t, ok)
	assert.Equal(t, domain.CodeNotFound, oopsErr.Code())
}

func TestUpdateHost_InvalidIP(t *testing.T) {
	h, ctx := newTestHandler(t)

	entry, err := h.AddHost(ctx, "192.168.1.1", "host1.local", nil, nil, nil)
	require.NoError(t, err)

	badIP := "not-an-ip"
	_, err = h.UpdateHost(ctx, entry.ID, &badIP, nil, nil, nil, nil, entry.Version)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid IP address")
}

func TestUpdateHost_NoChanges(t *testing.T) {
	h, ctx := newTestHandler(t)

	entry, err := h.AddHost(ctx, "192.168.1.1", "host1.local", nil, nil, nil)
	require.NoError(t, err)

	// Pass no update fields
	same, err := h.UpdateHost(ctx, entry.ID, nil, nil, nil, nil, nil, entry.Version)
	require.NoError(t, err)
	assert.Equal(t, entry.Version, same.Version)
}

func TestUpdateHost_MultipleChanges(t *testing.T) {
	h, ctx := newTestHandler(t)

	entry, err := h.AddHost(ctx, "192.168.1.1", "host1.local", nil, nil, nil)
	require.NoError(t, err)

	newIP := "10.0.0.1"
	newHostname := "new.local"
	newTags := []string{"tag1"}
	updated, err := h.UpdateHost(ctx, entry.ID, &newIP, &newHostname, nil, &newTags, nil, entry.Version)
	require.NoError(t, err)

	assert.Equal(t, "10.0.0.1", updated.IP)
	assert.Equal(t, "new.local", updated.Hostname)
	assert.Equal(t, []string{"tag1"}, updated.Tags)
	// Three changes: IP, hostname, tags → version 1 + 3 = "4"
	assert.Equal(t, "4", updated.Version)
}

// ---------- DeleteHost tests ----------

func TestDeleteHost_Exists(t *testing.T) {
	h, ctx := newTestHandler(t)

	entry, err := h.AddHost(ctx, "192.168.1.1", "host1.local", nil, nil, nil)
	require.NoError(t, err)

	err = h.DeleteHost(ctx, entry.ID, entry.Version)
	require.NoError(t, err)

	// Verify it's gone from reads
	_, err = h.GetHost(ctx, entry.ID)
	require.Error(t, err)

	oopsErr, ok := oops.AsOops(err)
	require.True(t, ok)
	assert.Equal(t, domain.CodeNotFound, oopsErr.Code())
}

func TestDeleteHost_NotFound(t *testing.T) {
	h, ctx := newTestHandler(t)

	fakeID := ulid.Make()
	err := h.DeleteHost(ctx, fakeID, "")
	require.Error(t, err)

	oopsErr, ok := oops.AsOops(err)
	require.True(t, ok)
	assert.Equal(t, domain.CodeNotFound, oopsErr.Code())
}

func TestDeleteHost_AlreadyDeleted(t *testing.T) {
	h, ctx := newTestHandler(t)

	entry, err := h.AddHost(ctx, "192.168.1.1", "host1.local", nil, nil, nil)
	require.NoError(t, err)

	require.NoError(t, h.DeleteHost(ctx, entry.ID, entry.Version))

	// Second delete should fail (not found since it's soft-deleted)
	err = h.DeleteHost(ctx, entry.ID, "2")
	require.Error(t, err)

	oopsErr, ok := oops.AsOops(err)
	require.True(t, ok)
	assert.Equal(t, domain.CodeNotFound, oopsErr.Code())
}

// ---------- GetHost tests ----------

func TestGetHost_Found(t *testing.T) {
	h, ctx := newTestHandler(t)

	created, err := h.AddHost(ctx, "192.168.1.1", "host1.local", nil, nil, nil)
	require.NoError(t, err)

	found, err := h.GetHost(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, created.ID, found.ID)
	assert.Equal(t, "192.168.1.1", found.IP)
}

func TestGetHost_NotFound(t *testing.T) {
	h, ctx := newTestHandler(t)

	_, err := h.GetHost(ctx, ulid.Make())
	require.Error(t, err)

	oopsErr, ok := oops.AsOops(err)
	require.True(t, ok)
	assert.Equal(t, domain.CodeNotFound, oopsErr.Code())
}

// ---------- ListHosts tests ----------

func TestListHosts_Empty(t *testing.T) {
	h, ctx := newTestHandler(t)

	entries, err := h.ListHosts(ctx)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestListHosts_MultipleEntries(t *testing.T) {
	h, ctx := newTestHandler(t)

	_, err := h.AddHost(ctx, "192.168.1.1", "host1.local", nil, nil, nil)
	require.NoError(t, err)
	_, err = h.AddHost(ctx, "192.168.1.2", "host2.local", nil, nil, nil)
	require.NoError(t, err)

	entries, err := h.ListHosts(ctx)
	require.NoError(t, err)
	assert.Len(t, entries, 2)
}

func TestListHosts_ExcludesDeleted(t *testing.T) {
	h, ctx := newTestHandler(t)

	e1, err := h.AddHost(ctx, "192.168.1.1", "host1.local", nil, nil, nil)
	require.NoError(t, err)
	_, err = h.AddHost(ctx, "192.168.1.2", "host2.local", nil, nil, nil)
	require.NoError(t, err)

	require.NoError(t, h.DeleteHost(ctx, e1.ID, e1.Version))

	entries, err := h.ListHosts(ctx)
	require.NoError(t, err)
	assert.Len(t, entries, 1)
	assert.Equal(t, "192.168.1.2", entries[0].IP)
}

// ---------- SearchHosts tests ----------

func TestSearchHosts_ByIP(t *testing.T) {
	h, ctx := newTestHandler(t)

	_, err := h.AddHost(ctx, "192.168.1.1", "host1.local", nil, nil, nil)
	require.NoError(t, err)
	_, err = h.AddHost(ctx, "10.0.0.1", "host2.local", nil, nil, nil)
	require.NoError(t, err)

	// IPPattern uses HasPrefix matching (not SQL LIKE)
	pattern := "192.168"
	entries, err := h.SearchHosts(ctx, domain.SearchFilter{IPPattern: &pattern})
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "192.168.1.1", entries[0].IP)
}

func TestSearchHosts_ByHostname(t *testing.T) {
	h, ctx := newTestHandler(t)

	_, err := h.AddHost(ctx, "192.168.1.1", "web.example.com", nil, nil, nil)
	require.NoError(t, err)
	_, err = h.AddHost(ctx, "10.0.0.1", "db.example.com", nil, nil, nil)
	require.NoError(t, err)

	// HostnamePattern uses case-insensitive Contains matching
	pattern := "web"
	entries, err := h.SearchHosts(ctx, domain.SearchFilter{HostnamePattern: &pattern})
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "web.example.com", entries[0].Hostname)
}

func TestSearchHosts_ByTags(t *testing.T) {
	h, ctx := newTestHandler(t)

	_, err := h.AddHost(ctx, "192.168.1.1", "host1.local", nil, []string{"web", "prod"}, nil)
	require.NoError(t, err)
	_, err = h.AddHost(ctx, "10.0.0.1", "host2.local", nil, []string{"db"}, nil)
	require.NoError(t, err)

	entries, err := h.SearchHosts(ctx, domain.SearchFilter{Tags: []string{"web"}})
	require.NoError(t, err)
	assert.Len(t, entries, 1)
	assert.Equal(t, "host1.local", entries[0].Hostname)
}

// ---------- nextVersion tests ----------

func TestNextVersion(t *testing.T) {
	v, err := nextVersion("")
	require.NoError(t, err)
	assert.Equal(t, "1", v)

	v, err = nextVersion("1")
	require.NoError(t, err)
	assert.Equal(t, "2", v)

	v, err = nextVersion("9")
	require.NoError(t, err)
	assert.Equal(t, "10", v)

	v, err = nextVersion("99")
	require.NoError(t, err)
	assert.Equal(t, "100", v)

	_, err = nextVersion("not-a-number")
	assert.Error(t, err)
}
