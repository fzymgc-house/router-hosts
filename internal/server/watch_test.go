package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
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

// readOneSnapshotBounded reads one entry-run-then-terminator snapshot off an
// open follow-mode stream, bounded by bound so a regression fails the test
// instead of hanging it. The stream is left open (unlike drainWatchHosts,
// which reads to io.EOF): follow mode never closes on its own.
func readOneSnapshotBounded(t *testing.T, stream hostsv1.HostsService_WatchHostsClient, bound time.Duration) ([]*hostsv1.HostEntry, *hostsv1.SnapshotComplete) {
	t.Helper()
	type result struct {
		entries  []*hostsv1.HostEntry
		complete *hostsv1.SnapshotComplete
		err      error
	}
	resCh := make(chan result, 1)
	go func() {
		var entries []*hostsv1.HostEntry
		for {
			resp, err := stream.Recv()
			if err != nil {
				resCh <- result{err: err}
				return
			}
			if e := resp.GetEntry(); e != nil {
				entries = append(entries, e)
			}
			if c := resp.GetComplete(); c != nil {
				resCh <- result{entries: entries, complete: c}
				return
			}
		}
	}()
	select {
	case res := <-resCh:
		require.NoError(t, res.err)
		return res.entries, res.complete
	case <-time.After(bound):
		t.Fatal("timed out waiting for a snapshot")
		return nil, nil
	}
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

// mutatingListAllStore wraps a real storage.Storage and commits one host
// mutation the first time ListAll is called, then delegates. It is the
// vehicle for TestService_WatchHosts_ChangeIDIsLowerBoundOnEntries and its
// follow-mode mirror below: it simulates a mutation landing between the
// server's LatestEventID read and its ListAll read.
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

// ---------------------------------------------------------------------------
// Follow mode
// ---------------------------------------------------------------------------

// followTestEnv sets up an in-process gRPC server with bufconn for
// follow-mode tests that need real wire framing (proto marshal/unmarshal,
// concurrent Send/Recv over an actual stream). Kept separate from
// service_test.go's serviceTestEnv so this file can pass extra
// ServiceOptions (WithSinkHealth) without churning that file.
type followTestEnv struct {
	client  hostsv1.HostsServiceClient
	handler *CommandHandler
	store   storage.Storage
	svc     *HostsServiceImpl
	conn    *grpc.ClientConn
}

func newFollowTestEnv(t *testing.T, extraOpts ...ServiceOption) *followTestEnv {
	t.Helper()
	ctx := context.Background()

	store, err := sqlite.New("file::memory:?mode=memory&cache=shared", slog.Default())
	require.NoError(t, err)
	require.NoError(t, store.Initialize(ctx))
	t.Cleanup(func() { _ = store.Close() })

	handler := NewCommandHandler(store)
	hostsGen := NewHostsFileGenerator("/dev/null")
	opts := append([]ServiceOption{WithHostsGenerator(hostsGen)}, extraOpts...)
	svc := NewHostsServiceImpl(handler, store, opts...)

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

	return &followTestEnv{
		client:  hostsv1.NewHostsServiceClient(conn),
		handler: handler,
		store:   store,
		svc:     svc,
		conn:    conn,
	}
}

// newBareFollowService builds a HostsServiceImpl with no gRPC/bufconn
// plumbing, for tests that drive WatchHosts's follow-mode handler directly
// against a fakeWatchHostsStream. This gives deterministic control over
// Send/Recv blocking behavior instead of depending on real network timing
// to reproduce the H1 teardown windows.
func newBareFollowService(t *testing.T, opts ...ServiceOption) *HostsServiceImpl {
	t.Helper()
	ctx := context.Background()
	store, err := sqlite.New("file::memory:?mode=memory&cache=shared", slog.Default())
	require.NoError(t, err)
	require.NoError(t, store.Initialize(ctx))
	t.Cleanup(func() { _ = store.Close() })

	handler := NewCommandHandler(store)
	return NewHostsServiceImpl(handler, store, opts...)
}

// fakeWatchHostsStream is a hand-built watchHostsStream. It lets a test
// script Send/Recv behavior precisely — blocking forever, erroring on the
// first call, returning io.EOF — instead of depending on real network
// timing to reproduce the two H1 teardown windows deterministically.
type fakeWatchHostsStream struct {
	ctx    context.Context
	sendFn func(*hostsv1.WatchHostsResponse) error
	recvFn func() (*hostsv1.WatchHostsRequest, error)
}

func (f *fakeWatchHostsStream) Send(r *hostsv1.WatchHostsResponse) error  { return f.sendFn(r) }
func (f *fakeWatchHostsStream) Recv() (*hostsv1.WatchHostsRequest, error) { return f.recvFn() }
func (f *fakeWatchHostsStream) Context() context.Context                  { return f.ctx }
func (f *fakeWatchHostsStream) SetHeader(metadata.MD) error               { return nil }
func (f *fakeWatchHostsStream) SendHeader(metadata.MD) error              { return nil }
func (f *fakeWatchHostsStream) SetTrailer(metadata.MD)                    {}
func (f *fakeWatchHostsStream) SendMsg(any) error                         { return nil }
func (f *fakeWatchHostsStream) RecvMsg(any) error                         { return nil }

// recvQueueThenBlock returns a recvFn that delivers each message in msgs, in
// order, then blocks until ctx is done (simulating a client that goes
// silent without closing its send side). Called from a single goroutine
// only (watchFollowRecv's own loop), so it needs no internal locking.
func recvQueueThenBlock(ctx context.Context, msgs ...*hostsv1.WatchHostsRequest) func() (*hostsv1.WatchHostsRequest, error) {
	idx := 0
	return func() (*hostsv1.WatchHostsRequest, error) {
		if idx < len(msgs) {
			m := msgs[idx]
			idx++
			return m, nil
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
}

// testLeafCert is declared in peercn_test.go; reused here to manufacture a
// verified-identity stream context without a real mTLS handshake.

// newVerifiedFollowContext builds a context carrying a verified mTLS peer
// identity, the same construction TestCommonNameFromContext uses, so
// follow-mode tests can exercise the per-identity recording path without a
// real TLS handshake. Cancellable so goroutines driven against it (via
// fakeWatchHostsStream) can be released at test cleanup.
func newVerifiedFollowContext(t *testing.T, cn string) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	p := &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{{testLeafCert(cn)}},
			},
		},
	}
	return peer.NewContext(ctx, p)
}

func TestService_WatchHosts_FollowInitialSnapshot(t *testing.T) {
	env := newFollowTestEnv(t)
	ctx := context.Background()

	_, err := env.handler.AddHost(ctx, "192.168.1.1", "seed.local", nil, nil, nil)
	require.NoError(t, err)

	stream, err := env.client.WatchHosts(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&hostsv1.WatchHostsRequest{Follow: true}))

	entries, complete := readOneSnapshotBounded(t, stream, waitBound)
	assert.Len(t, entries, 1)
	assert.EqualValues(t, 1, complete.GetCount())
	assert.Equal(t, TemplateContractVersion, complete.GetContractVersion())
}

func TestService_WatchHosts_FollowPushesOnMutation(t *testing.T) {
	env := newFollowTestEnv(t)
	ctx := context.Background()

	stream, err := env.client.WatchHosts(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&hostsv1.WatchHostsRequest{Follow: true}))

	_, initial := readOneSnapshotBounded(t, stream, waitBound)
	assert.EqualValues(t, 0, initial.GetCount())

	// Through the front door (the service's AddHost, not the handler
	// directly): this is what fires the change notification.
	_, err = env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "192.168.1.1",
		Hostname:  "new.local",
	})
	require.NoError(t, err)

	entries, complete := readOneSnapshotBounded(t, stream, waitBound)
	assert.Len(t, entries, 1)
	assert.EqualValues(t, 1, complete.GetCount())
	assert.Equal(t, "new.local", entries[0].GetHostname())
}

// TestService_WatchHosts_FollowConvergesAfterBurst replaces the flaky
// "coalesces burst" claim with three deterministic assertions (review M2):
// an upper bound of N+1 snapshots (the loop below hard-caps reads at that
// count), final-state entry equality, and change-ID equality with the
// store's LatestEventID. It does NOT assert a strict lower bound on
// coalescing — that deterministic proof lives in
// TestChangeNotifier_CoalescesBurst, which controls its own timing.
func TestService_WatchHosts_FollowConvergesAfterBurst(t *testing.T) {
	env := newFollowTestEnv(t)
	ctx := context.Background()

	stream, err := env.client.WatchHosts(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&hostsv1.WatchHostsRequest{Follow: true}))
	_, initial := readOneSnapshotBounded(t, stream, waitBound)
	assert.EqualValues(t, 0, initial.GetCount())

	const n = 20
	for i := range n {
		_, err := env.client.AddHost(ctx, &hostsv1.AddHostRequest{
			IpAddress: "10.0.0.1",
			Hostname:  hostForBurst(i),
		})
		require.NoError(t, err)
	}

	finalLatest, err := env.store.LatestEventID(ctx)
	require.NoError(t, err)

	var (
		snapshotCount int
		lastEntries   []*hostsv1.HostEntry
		lastComplete  *hostsv1.SnapshotComplete
	)
	for snapshotCount < n+1 {
		lastEntries, lastComplete = readOneSnapshotBounded(t, stream, waitBound)
		snapshotCount++
		if lastComplete.GetChangeId() == finalLatest.String() {
			break
		}
	}

	assert.LessOrEqual(t, snapshotCount, n+1, "at most N+1 snapshots for N mutations")
	require.Equal(t, finalLatest.String(), lastComplete.GetChangeId(), "final snapshot must carry the store's current change ID")
	assert.Len(t, lastEntries, n, "final snapshot must reflect the final entry count")
}

func hostForBurst(i int) string {
	return "burst" + string(rune('a'+i%26)) + string(rune('a'+(i/26))) + ".local"
}

// TestService_WatchHosts_FollowIgnoresReportedChangeIDForSendDecision is the
// mechanical D-21 gate: a client reporting the server's CURRENT change ID on
// its opening message must still receive a complete snapshot. If a
// server-side skip is ever added, this test goes red.
func TestService_WatchHosts_FollowIgnoresReportedChangeIDForSendDecision(t *testing.T) {
	env := newFollowTestEnv(t)
	ctx := context.Background()

	_, err := env.client.AddHost(ctx, &hostsv1.AddHostRequest{IpAddress: "192.168.1.1", Hostname: "seed.local"})
	require.NoError(t, err)

	latest, err := env.store.LatestEventID(ctx)
	require.NoError(t, err)

	stream, err := env.client.WatchHosts(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&hostsv1.WatchHostsRequest{
		Follow: true,
		Status: &hostsv1.SinkStatus{RenderedChangeId: latest.String()},
	}))

	entries, complete := readOneSnapshotBounded(t, stream, waitBound)
	assert.Len(t, entries, 1, "a full snapshot must still arrive even when the opening message reports the server's current change ID")
	assert.Equal(t, latest.String(), complete.GetChangeId())
}

func TestService_WatchHosts_FollowRecordsStatus(t *testing.T) {
	health := NewSinkHealth()
	svc := newBareFollowService(t, WithSinkHealth(health))

	streamCtx := newVerifiedFollowContext(t, "sink-status")
	statusMsg := &hostsv1.WatchHostsRequest{
		Status: &hostsv1.SinkStatus{
			LastSuccessUnix:     time.Now().Unix(),
			ConsecutiveFailures: 3,
			ContractVersion:     "1",
			RenderedChangeId:    "some-change-id",
		},
	}
	stream := &fakeWatchHostsStream{
		ctx:    streamCtx,
		sendFn: func(*hostsv1.WatchHostsResponse) error { return nil },
		recvFn: recvQueueThenBlock(streamCtx, statusMsg),
	}

	go func() { _ = svc.watchFollow(stream, &hostsv1.WatchHostsRequest{Follow: true}) }()

	require.Eventually(t, func() bool {
		return len(health.Snapshot().States) == 1
	}, waitBound, 10*time.Millisecond, "mid-stream status message was never recorded")

	st, ok := health.Snapshot().States["sink-status"]
	require.True(t, ok)
	assert.Equal(t, int64(3), st.ConsecutiveFailures)
	assert.Equal(t, "1", st.ContractVersion)
	assert.Equal(t, "some-change-id", st.RenderedChangeID)
}

// TestService_WatchHosts_FollowRecordsOpeningStatus pins review L3: a
// status payload on the OPENING message is recorded too, not discarded.
func TestService_WatchHosts_FollowRecordsOpeningStatus(t *testing.T) {
	health := NewSinkHealth()
	svc := newBareFollowService(t, WithSinkHealth(health))

	streamCtx := newVerifiedFollowContext(t, "sink-opening")
	first := &hostsv1.WatchHostsRequest{
		Follow: true,
		Status: &hostsv1.SinkStatus{
			ConsecutiveFailures: 7,
			ContractVersion:     "1",
		},
	}
	stream := &fakeWatchHostsStream{
		ctx:    streamCtx,
		sendFn: func(*hostsv1.WatchHostsResponse) error { return nil },
		recvFn: recvQueueThenBlock(streamCtx),
	}

	go func() { _ = svc.watchFollow(stream, first) }()

	require.Eventually(t, func() bool {
		return len(health.Snapshot().States) == 1
	}, waitBound, 10*time.Millisecond, "opening status message was never recorded")

	st := health.Snapshot().States["sink-opening"]
	assert.Equal(t, int64(7), st.ConsecutiveFailures)
}

// TestService_WatchHosts_FollowSendErrorReturnsWhileRecvIdle is Codex's H1
// path: Send fails while the client is silent (Recv has nothing pending and
// never will). Before this test was accepted, wg.Wait()-style teardown was
// temporarily reintroduced and this test was confirmed to hang (see
// SUMMARY.md).
func TestService_WatchHosts_FollowSendErrorReturnsWhileRecvIdle(t *testing.T) {
	health := NewSinkHealth()
	svc := newBareFollowService(t, WithSinkHealth(health))

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	stream := &fakeWatchHostsStream{
		ctx: ctx,
		sendFn: func(*hostsv1.WatchHostsResponse) error {
			return errors.New("simulated send failure")
		},
		recvFn: recvQueueThenBlock(ctx), // no messages: blocks, simulating a silent client
	}

	done := make(chan error, 1)
	go func() { done <- svc.watchFollow(stream, &hostsv1.WatchHostsRequest{Follow: true}) }()

	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(waitBound):
		t.Fatal("handler did not return after Send failed while Recv was idle")
	}

	assert.EqualValues(t, 0, health.Snapshot().Connected)
}

// TestService_WatchHosts_FollowRecvEOFReturnsWhileSendBlocked is pi's H1
// path: the client closes its send side (io.EOF) while the sender is
// blocked in Send on flow control. Before this test was accepted,
// wg.Wait()-style teardown was temporarily reintroduced and this test was
// confirmed to hang (see SUMMARY.md).
func TestService_WatchHosts_FollowRecvEOFReturnsWhileSendBlocked(t *testing.T) {
	health := NewSinkHealth()
	svc := newBareFollowService(t, WithSinkHealth(health))

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// sendBlock is deliberately never closed: a real stalled Send responds
	// only to the underlying stream tearing down, not to any child context
	// this handler derives and cancels itself (that is the whole H1 point),
	// so this fake must not give Send a ctx.Done() escape hatch either — it
	// would make this test pass even under the pre-review teardown it is
	// meant to catch.
	sendBlock := make(chan struct{})
	stream := &fakeWatchHostsStream{
		ctx: ctx,
		sendFn: func(*hostsv1.WatchHostsResponse) error {
			<-sendBlock
			return nil
		},
		recvFn: func() (*hostsv1.WatchHostsRequest, error) {
			return nil, io.EOF
		},
	}

	done := make(chan error, 1)
	go func() { done <- svc.watchFollow(stream, &hostsv1.WatchHostsRequest{Follow: true}) }()

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(waitBound):
		t.Fatal("handler did not return while Send was blocked and Recv observed EOF")
	}

	assert.EqualValues(t, 0, health.Snapshot().Connected)
}

// TestService_WatchHosts_FollowWithoutPeerIdentityStillStreams covers review
// L11: an unverifiable peer identity still streams snapshots, still moves
// the label-free connected count, records no per-identity health, and
// increments the identity-failure signal.
func TestService_WatchHosts_FollowWithoutPeerIdentityStillStreams(t *testing.T) {
	health := NewSinkHealth()
	svc := newBareFollowService(t, WithSinkHealth(health))

	ctx, cancel := context.WithCancel(context.Background()) // no peer info attached
	t.Cleanup(cancel)

	var sendCount atomic.Int64
	stream := &fakeWatchHostsStream{
		ctx: ctx,
		sendFn: func(*hostsv1.WatchHostsResponse) error {
			sendCount.Add(1)
			return nil
		},
		recvFn: recvQueueThenBlock(ctx),
	}

	go func() { _ = svc.watchFollow(stream, &hostsv1.WatchHostsRequest{Follow: true}) }()

	require.Eventually(t, func() bool {
		return sendCount.Load() > 0
	}, waitBound, 10*time.Millisecond, "snapshot never streamed without a verified identity")

	snap := health.Snapshot()
	assert.EqualValues(t, 1, snap.IdentityFailures)
	assert.Empty(t, snap.States)
	assert.EqualValues(t, 1, snap.Connected)
}

func TestService_WatchHosts_FollowContextCancelReturns(t *testing.T) {
	health := NewSinkHealth()
	svc := newBareFollowService(t, WithSinkHealth(health))

	ctx, cancel := context.WithCancel(context.Background())

	stream := &fakeWatchHostsStream{
		ctx:    ctx,
		sendFn: func(*hostsv1.WatchHostsResponse) error { return nil },
		recvFn: recvQueueThenBlock(ctx),
	}

	done := make(chan error, 1)
	go func() { done <- svc.watchFollow(stream, &hostsv1.WatchHostsRequest{Follow: true}) }()

	cancel()

	select {
	case <-done:
	case <-time.After(waitBound):
		t.Fatal("handler did not return after the stream context was cancelled")
	}
}

// TestService_WatchHosts_FollowChurnDoesNotAccumulate is review M9: repeated
// connect/disconnect cycles leave the connected count at zero and do not
// accumulate goroutines, proving the deliberately non-joining handler does
// not leak.
func TestService_WatchHosts_FollowChurnDoesNotAccumulate(t *testing.T) {
	health := NewSinkHealth()
	env := newFollowTestEnv(t, WithSinkHealth(health))
	ctx := context.Background()

	baseline := runtime.NumGoroutine()

	const cycles = 20
	for i := range cycles {
		streamCtx, cancel := context.WithCancel(ctx)
		stream, err := env.client.WatchHosts(streamCtx)
		require.NoError(t, err)
		require.NoError(t, stream.Send(&hostsv1.WatchHostsRequest{Follow: true}))

		readOneSnapshotBounded(t, stream, waitBound)

		require.Eventually(t, func() bool {
			return health.Snapshot().Connected == 1
		}, waitBound, 5*time.Millisecond, "connect never observed on cycle %d", i)

		cancel()

		require.Eventually(t, func() bool {
			return health.Snapshot().Connected == 0
		}, waitBound, 5*time.Millisecond, "disconnect never observed on cycle %d", i)
	}

	// The deterministic assertion: driven by the deferred Disconnect and
	// cannot pass while a handler is still running.
	assert.EqualValues(t, 0, health.Snapshot().Connected)

	// The secondary check, with generous slack: the Go runtime and grpc-go
	// both hold pools that make an exact goroutine count flaky.
	require.Eventually(t, func() bool {
		return runtime.NumGoroutine() <= baseline+50
	}, waitBound, 20*time.Millisecond, "goroutine count grew unexpectedly after %d connect/disconnect cycles", cycles)
}

// TestService_WatchHosts_FollowSnapshotIDIsLowerBoundOnEntries is the
// follow-mode mirror of TestService_WatchHosts_ChangeIDIsLowerBoundOnEntries
// (review H1): the shared sendSnapshot helper must derive the change ID
// before ListAll in follow mode too.
func TestService_WatchHosts_FollowSnapshotIDIsLowerBoundOnEntries(t *testing.T) {
	ctx := context.Background()

	store, err := sqlite.New("file::memory:?mode=memory&cache=shared", slog.Default())
	require.NoError(t, err)
	require.NoError(t, store.Initialize(ctx))
	t.Cleanup(func() { _ = store.Close() })

	handler := NewCommandHandler(store)
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

	stream, err := client.WatchHosts(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&hostsv1.WatchHostsRequest{Follow: true}))

	entries, first := readOneSnapshotBounded(t, stream, waitBound)

	found := false
	for _, e := range entries {
		if e.GetHostname() == "mid-read.local" {
			found = true
		}
	}
	assert.True(t, found, "entry set must contain the mid-ListAll mutation")

	postFirstLatest, err := store.LatestEventID(ctx)
	require.NoError(t, err)
	assert.Less(t, first.GetChangeId(), postFirstLatest.String())

	// The decorator commits its mutation directly to storage, which never
	// reaches regenerateOutputs and therefore never notifies (there are
	// only two notify call sites in the package and neither is on that
	// path). Waking the sender explicitly is why a second snapshot arrives
	// at all — nothing in production would have notified for a mutation
	// made behind the service's back either, so this is not a defect in
	// the decorator.
	svc.RegenerateOutputs(ctx)

	_, second := readOneSnapshotBounded(t, stream, waitBound)
	assert.Greater(t, second.GetChangeId(), first.GetChangeId())
}
