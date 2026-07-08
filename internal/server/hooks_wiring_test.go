package server

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fzymgc-house/router-hosts/internal/config"
	"github.com/fzymgc-house/router-hosts/internal/storage/sqlite"
)

// hookWiringStore returns an isolated in-memory store. The DSN embeds t.Name()
// so a shared process-global cache can't bleed aggregates across parallel tests.
func hookWiringStore(t *testing.T) *sqlite.Storage {
	t.Helper()
	ctx := context.Background()
	store, err := sqlite.New(fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name()), slog.Default())
	require.NoError(t, err)
	require.NoError(t, store.Initialize(ctx))
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// writeSentinelHook writes "<event>:<entry_count>" to sentinelPath so a test can
// observe whether — and with what context — the hook ran.
func writeSentinelHook(name, sentinelPath string) config.HookDefinition {
	return config.HookDefinition{
		Name:    name,
		Command: fmt.Sprintf(`printf '%%s:%%s' "$ROUTER_HOSTS_EVENT" "$ROUTER_HOSTS_ENTRY_COUNT" > %q`, sentinelPath),
	}
}

// sentinelHooks builds an executor whose success/failure hooks write to the two
// returned sentinel paths.
func sentinelHooks(dir string) (hooks *HookExecutor, successSentinel, failureSentinel string) {
	successSentinel = filepath.Join(dir, "success")
	failureSentinel = filepath.Join(dir, "failure")
	hooks = NewHookExecutor(
		[]config.HookDefinition{writeSentinelHook("on-success", successSentinel)},
		[]config.HookDefinition{writeSentinelHook("on-failure", failureSentinel)},
		5*time.Second,
		slog.Default(),
	)
	return hooks, successSentinel, failureSentinel
}

// seedHosts adds n entries via the handler directly, which does not itself
// trigger regeneration (that happens at the service layer).
func seedHosts(t *testing.T, handler *CommandHandler, n int) {
	t.Helper()
	ctx := context.Background()
	for i := range n {
		_, err := handler.AddHost(ctx, fmt.Sprintf("192.168.1.%d", 10+i), fmt.Sprintf("h%d.example.com", i), nil, nil, nil)
		require.NoError(t, err)
	}
}

// router-hosts-62o: configured on_success hooks must fire after a successful
// regeneration, carrying the documented event/entry-count env.
func TestRegenerateOutputs_FiresOnSuccessHook(t *testing.T) {
	ctx := context.Background()
	store := hookWiringStore(t)
	handler := NewCommandHandler(store)
	seedHosts(t, handler, 2)

	dir := t.TempDir()
	hooks, successSentinel, failureSentinel := sentinelHooks(dir)
	gen := NewHostsFileGenerator(filepath.Join(dir, "hosts"))
	svc := NewHostsServiceImpl(handler, store, WithHostsGenerator(gen), WithHookExecutor(hooks))

	svc.RegenerateOutputs(ctx)

	got, err := os.ReadFile(successSentinel)
	require.NoError(t, err)
	assert.Equal(t, "success:2", string(got))
	assert.NoFileExists(t, failureSentinel)
}

// A generator error must fire on_failure — and the entry count reported to the
// hook is the store's real count, not zero (router-hosts-9im.2).
func TestRegenerateOutputs_FiresOnFailureHook(t *testing.T) {
	ctx := context.Background()
	store := hookWiringStore(t)
	handler := NewCommandHandler(store)
	seedHosts(t, handler, 2)

	dir := t.TempDir()
	hooks, successSentinel, failureSentinel := sentinelHooks(dir)
	// Parent dir does not exist, so atomicWriteFile's os.CreateTemp fails.
	gen := NewHostsFileGenerator(filepath.Join(dir, "missing-subdir", "hosts"))
	svc := NewHostsServiceImpl(handler, store, WithHostsGenerator(gen), WithHookExecutor(hooks))

	svc.RegenerateOutputs(ctx)

	got, err := os.ReadFile(failureSentinel)
	require.NoError(t, err)
	assert.Equal(t, "failure:2", string(got))
	assert.NoFileExists(t, successSentinel)
}

// One generator failing among several still fires on_failure (not on_success),
// and the count stays correct even though another generator succeeded.
func TestRegenerateOutputs_PartialFailureFiresFailureHook(t *testing.T) {
	ctx := context.Background()
	store := hookWiringStore(t)
	handler := NewCommandHandler(store)
	seedHosts(t, handler, 2)

	dir := t.TempDir()
	hooks, successSentinel, failureSentinel := sentinelHooks(dir)
	goodGen := NewHostsFileGenerator(filepath.Join(dir, "hosts"))
	badGen := NewDnsmasqConfGenerator(filepath.Join(dir, "missing-subdir", "dnsmasq.conf"))
	svc := NewHostsServiceImpl(handler, store,
		WithHostsGenerator(goodGen), WithDnsmasqGenerator(badGen), WithHookExecutor(hooks))

	svc.RegenerateOutputs(ctx)

	got, err := os.ReadFile(failureSentinel)
	require.NoError(t, err)
	assert.Equal(t, "failure:2", string(got))
	assert.NoFileExists(t, successSentinel)
}

// Hooks react to output writes: with no generator configured, neither fires.
func TestRegenerateOutputs_NoHooksWhenNoGenerator(t *testing.T) {
	ctx := context.Background()
	store := hookWiringStore(t)
	handler := NewCommandHandler(store)

	dir := t.TempDir()
	hooks, successSentinel, failureSentinel := sentinelHooks(dir)
	svc := NewHostsServiceImpl(handler, store, WithHookExecutor(hooks))

	svc.RegenerateOutputs(ctx)

	assert.NoFileExists(t, successSentinel)
	assert.NoFileExists(t, failureSentinel)
}
