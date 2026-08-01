package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
	"github.com/fzymgc-house/router-hosts/internal/domain"
	"github.com/fzymgc-house/router-hosts/internal/storage"
	"github.com/fzymgc-house/router-hosts/internal/storage/sqlite"
)

// drainWatchHosts drains a WatchHosts client stream into its entries plus
// terminator, failing the test if the stream ends without a terminator.
func drainWatchHosts(t *testing.T, stream hostsv1.HostsService_WatchHostsClient) ([]*hostsv1.HostEntry, *hostsv1.SnapshotComplete) {
	t.Helper()
	var entries []*hostsv1.HostEntry
	var complete *hostsv1.SnapshotComplete
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		if e := resp.GetEntry(); e != nil {
			entries = append(entries, e)
		}
		if c := resp.GetComplete(); c != nil {
			complete = c
		}
	}
	require.NotNil(t, complete, "stream ended without a SnapshotComplete terminator")
	return entries, complete
}

// oneShotWatch opens a non-follow WatchHosts request/response round trip.
func oneShotWatch(t *testing.T, ctx context.Context, client hostsv1.HostsServiceClient) ([]*hostsv1.HostEntry, *hostsv1.SnapshotComplete) {
	t.Helper()
	stream, err := client.WatchHosts(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&hostsv1.WatchHostsRequest{Follow: false}))
	require.NoError(t, stream.CloseSend())
	return drainWatchHosts(t, stream)
}

func TestService_WatchHosts_OneShotSnapshot(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	const n = 3
	for i := range n {
		_, err := env.handler.AddHost(ctx, "192.168.1.1", "host"+string(rune('a'+i))+".local", nil, nil, nil)
		require.NoError(t, err)
	}

	entries, complete := oneShotWatch(t, ctx, env.client)
	assert.Len(t, entries, n)
	assert.EqualValues(t, n, complete.GetCount())
	assert.Equal(t, TemplateContractVersion, complete.GetContractVersion())

	latest, err := env.store.LatestEventID(ctx)
	require.NoError(t, err)
	assert.Equal(t, latest.String(), complete.GetChangeId())
}

func TestService_WatchHosts_ChangeIDStableForUnchangedState(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	_, err := env.handler.AddHost(ctx, "192.168.1.1", "host.local", nil, nil, nil)
	require.NoError(t, err)

	_, first := oneShotWatch(t, ctx, env.client)
	_, second := oneShotWatch(t, ctx, env.client)

	assert.Equal(t, first.GetChangeId(), second.GetChangeId())
}

func TestService_WatchHosts_ChangeIDAdvancesOnMutation(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	_, err := env.handler.AddHost(ctx, "192.168.1.1", "seed.local", nil, nil, nil)
	require.NoError(t, err)

	prevID, err := env.store.LatestEventID(ctx)
	require.NoError(t, err)
	prev := prevID.String()

	for i := range 50 {
		_, err := env.handler.AddHost(ctx, "10.0.0.1", "rapid"+string(rune('a'+i%26))+string(rune('a'+(i/26)))+".local", nil, nil, nil)
		require.NoError(t, err)

		nextID, err := env.store.LatestEventID(ctx)
		require.NoError(t, err)
		next := nextID.String()

		assert.Greater(t, next, prev, "iteration %d: change ID must strictly advance", i)
		prev = next
	}
}

func TestService_WatchHosts_ChangeIDEmptyStore(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	_, complete := oneShotWatch(t, ctx, env.client)
	assert.Equal(t, storage.ZeroChangeID, complete.GetChangeId())
}

func TestService_WatchHosts_StreamsPerEntry(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	const n = 3
	for i := range n {
		_, err := env.handler.AddHost(ctx, "192.168.1.1", "entry"+string(rune('a'+i))+".local", nil, nil, nil)
		require.NoError(t, err)
	}

	stream, err := env.client.WatchHosts(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&hostsv1.WatchHostsRequest{Follow: false}))
	require.NoError(t, stream.CloseSend())

	var entryCount, completeCount int
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		if e := resp.GetEntry(); e != nil {
			entryCount++
		}
		if c := resp.GetComplete(); c != nil {
			completeCount++
			assert.EqualValues(t, n, c.GetCount())
		}
	}

	assert.Equal(t, n, entryCount, "exactly one message per entry")
	assert.Equal(t, 1, completeCount, "exactly one terminator")
	// The oneof makes more than one entry per message structurally
	// impossible; the message-count relationship is the assertion that
	// stands in for "every entry-arm message carried exactly one entry".
	assert.Equal(t, n+1, entryCount+completeCount, "total messages must equal entry count plus one terminator")
}

func TestService_WatchHosts_EmptyStoreSendsTerminatorOnly(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	entries, complete := oneShotWatch(t, ctx, env.client)
	assert.Empty(t, entries)
	assert.EqualValues(t, 0, complete.GetCount())
}

func TestService_WatchHosts_FollowUnimplemented(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	stream, err := env.client.WatchHosts(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&hostsv1.WatchHostsRequest{Follow: true}))
	require.NoError(t, stream.CloseSend())

	_, err = stream.Recv()
	require.Error(t, err)
	assert.Equal(t, codes.Unimplemented, status.Code(err))
}

// mutatingListAllStore wraps a real storage.Storage and commits one host
// mutation the first time ListAll is called, then delegates. It is the
// vehicle for TestService_WatchHosts_ChangeIDIsLowerBoundOnEntries: it
// simulates a mutation landing between the server's LatestEventID read and
// its ListAll read.
type mutatingListAllStore struct {
	storage.Storage
	handler *CommandHandler
	mutated bool
}

func (m *mutatingListAllStore) ListAll(ctx context.Context) ([]domain.HostEntry, error) {
	if !m.mutated {
		m.mutated = true
		if _, err := m.handler.AddHost(ctx, "10.10.10.10", "mid-read.local", nil, nil, nil); err != nil {
			return nil, err
		}
	}
	return m.Storage.ListAll(ctx)
}

func TestService_WatchHosts_ChangeIDIsLowerBoundOnEntries(t *testing.T) {
	ctx := context.Background()

	store, err := sqlite.New("file::memory:?mode=memory&cache=shared", slog.Default())
	require.NoError(t, err)
	require.NoError(t, store.Initialize(ctx))
	t.Cleanup(func() { _ = store.Close() })

	handler := NewCommandHandler(store)
	// Seed one entry so the decorator's mid-read mutation is not the store's
	// very first event.
	_, err = handler.AddHost(ctx, "192.168.1.1", "seed.local", nil, nil, nil)
	require.NoError(t, err)

	decorated := &mutatingListAllStore{Storage: store, handler: handler}
	hostsGen := NewHostsFileGenerator("/dev/null")
	svc := NewHostsServiceImpl(handler, decorated, WithHostsGenerator(hostsGen))

	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	hostsv1.RegisterHostsServiceServer(srv, svc)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	client := hostsv1.NewHostsServiceClient(conn)
	entries, complete := oneShotWatch(t, ctx, client)

	// The decorator's mutation must be visible in the entry set (it landed
	// before ListAll returned).
	found := false
	for _, e := range entries {
		if e.GetHostname() == "mid-read.local" {
			found = true
		}
	}
	assert.True(t, found, "entry set must contain the mid-ListAll mutation")

	postStreamLatest, err := store.LatestEventID(ctx)
	require.NoError(t, err)

	// The signature of a lower bound: the terminator's change ID is
	// strictly LESS than the log's post-stream maximum, because the ID was
	// captured before the mutation that the entries already contain.
	assert.Less(t, complete.GetChangeId(), postStreamLatest.String())
}
