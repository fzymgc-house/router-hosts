package commands

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	texttemplate "text/template"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
	"github.com/fzymgc-house/router-hosts/internal/client"
	"github.com/fzymgc-house/router-hosts/internal/client/template"
	"github.com/fzymgc-house/router-hosts/internal/contract"
)

// --- shared test helpers ---

// addHost runs "host add" against the bufconn server setupCmdTest wired up,
// so a watch session under test observes a real mutation.
func addHost(t *testing.T, ip, hostname string) {
	t.Helper()
	root := NewRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"--quiet", "host", "add", "--ip", ip, "--hostname", hostname})
	require.NoError(t, root.Execute())
}

// discoverChangeID renders the current server change ID via a one-shot
// render, so a test can pre-seed a sidecar whose rendered_change_id matches
// exactly what a following watch session will see on its opening snapshot.
func discoverChangeID(t *testing.T) string {
	t.Helper()
	root := NewRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	tmplPath := filepath.Join(t.TempDir(), "changeid.tmpl")
	require.NoError(t, os.WriteFile(tmplPath, []byte(testContractVersionBlock+`{{.ChangeID}}`), 0o644))
	root.SetArgs([]string{"render", "--template", tmplPath})
	require.NoError(t, root.Execute())
	return out.String()
}

// startWatch runs the "watch" command in a goroutine against ctx, returning
// a channel that receives its eventual error. rootOpts is passed through to
// NewRootCmd (e.g. WithWatchPolicy).
func startWatch(_ *testing.T, ctx context.Context, rootOpts []RootOption, args ...string) chan error {
	root := NewRootCmd(rootOpts...)
	root.SetArgs(append([]string{"watch"}, args...))
	errCh := make(chan error, 1)
	go func() {
		errCh <- root.ExecuteContext(ctx)
	}()
	return errCh
}

// requireBoundedNoError waits for errCh, bounded by bound, and requires a
// nil error. Every test using this fails loudly rather than hanging if a
// regression stops the watch command from returning.
func requireBoundedNoError(t *testing.T, errCh chan error, bound time.Duration) {
	t.Helper()
	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(bound):
		t.Fatal("timed out waiting for the watch command to return")
	}
}

// waitForFileContent polls path until it contains want or bound elapses,
// failing the test on timeout instead of hanging it.
func waitForFileContent(t *testing.T, path, want string, bound time.Duration) {
	t.Helper()
	deadline := time.Now().Add(bound)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil && string(data) == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	data, _ := os.ReadFile(path)
	t.Fatalf("timed out waiting for %s to contain %q (last read: %q)", path, want, string(data))
}

// mustParseTestTemplate parses a template declaring the current contract
// version followed by body.
func mustParseTestTemplate(t *testing.T, body string) *texttemplate.Template {
	t.Helper()
	tmpl, err := template.Parse("test", testContractVersionBlock+body)
	require.NoError(t, err)
	return tmpl
}

// entryResp/completeResp build WatchHostsResponse messages for the fake
// stream used by the unit-level cycle tests below.
func entryResp(ip, hostname string) *hostsv1.WatchHostsResponse {
	return &hostsv1.WatchHostsResponse{
		Payload: &hostsv1.WatchHostsResponse_Entry{
			Entry: &hostsv1.HostEntry{IpAddress: ip, Hostname: hostname},
		},
	}
}

func completeResp(changeID string, count int32, contractVersion string) *hostsv1.WatchHostsResponse {
	return &hostsv1.WatchHostsResponse{
		Payload: &hostsv1.WatchHostsResponse_Complete{
			Complete: &hostsv1.SnapshotComplete{
				ChangeId:        changeID,
				Count:           count,
				ContractVersion: contractVersion,
				GeneratedAt:     timestamppb.Now(),
			},
		},
	}
}

// --- fake WatchHosts stream, for deterministic unit-level cycle tests ---

// fakeWatchStream implements hostsv1.HostsService_WatchHostsClient
// (grpc.BidiStreamingClient[WatchHostsRequest, WatchHostsResponse]) without
// any network, so the sink-cycle behaviors in runWatchRecvLoop/runWatchCycle
// can be driven deterministically instead of timed over a real stream —
// the same rationale internal/server/watch_test.go's fakeWatchHostsStream
// documents for the server side.
type fakeWatchStream struct {
	// ctx stands in for the real gRPC ClientStream's own context, which is
	// exactly what Context() below returns on the genuine type too.
	ctx context.Context

	mu      sync.Mutex
	sent    []*hostsv1.WatchHostsRequest
	toRecv  []*hostsv1.WatchHostsResponse
	recvIdx int
	recvFn  func() (*hostsv1.WatchHostsResponse, error)

	// blockSend makes every Send call AFTER the first (the opening
	// follow=true request, which must succeed immediately or runWatch
	// never reaches the point of spawning the ticker/recv loop at all)
	// block until ctx is done, then wait an additional sendDoneDelay
	// before returning ctx.Err() — simulating a status-ticker Send stalled
	// on flow control that takes some visible time to actually unwind
	// after cancellation.
	blockSend     bool
	sendDoneDelay time.Duration

	// blockRecvUntilDone makes Recv (once any scripted responses are
	// exhausted) block until ctx is done and then return immediately,
	// simulating a live idle stream waiting for the next server push
	// rather than one that has already hung up.
	blockRecvUntilDone bool
}

func (f *fakeWatchStream) Send(req *hostsv1.WatchHostsRequest) error {
	f.mu.Lock()
	f.sent = append(f.sent, req)
	callNum := len(f.sent)
	block := f.blockSend
	delay := f.sendDoneDelay
	f.mu.Unlock()

	if block && callNum > 1 {
		<-f.ctx.Done()
		if delay > 0 {
			time.Sleep(delay)
		}
		return f.ctx.Err()
	}
	return nil
}

func (f *fakeWatchStream) Recv() (*hostsv1.WatchHostsResponse, error) {
	if f.recvFn != nil {
		return f.recvFn()
	}
	f.mu.Lock()
	if f.recvIdx < len(f.toRecv) {
		r := f.toRecv[f.recvIdx]
		f.recvIdx++
		f.mu.Unlock()
		return r, nil
	}
	blockUntilDone := f.blockRecvUntilDone
	f.mu.Unlock()

	if blockUntilDone {
		<-f.ctx.Done()
		return nil, f.ctx.Err()
	}
	return nil, io.EOF
}

func (f *fakeWatchStream) Header() (metadata.MD, error) { return nil, nil }
func (f *fakeWatchStream) Trailer() metadata.MD         { return nil }
func (f *fakeWatchStream) CloseSend() error             { return nil }
func (f *fakeWatchStream) Context() context.Context     { return f.ctx }
func (f *fakeWatchStream) SendMsg(any) error            { return nil }
func (f *fakeWatchStream) RecvMsg(any) error            { return nil }

// fakeHostsServiceClient embeds the full hostsv1.HostsServiceClient
// interface (nil by default) and overrides only WatchHosts, the one method
// runWatch calls — the standard Go "embed the interface, implement what you
// need" fake pattern.
type fakeHostsServiceClient struct {
	hostsv1.HostsServiceClient
	watchFn func(ctx context.Context, opts ...grpc.CallOption) (hostsv1.HostsService_WatchHostsClient, error)
}

func (f *fakeHostsServiceClient) WatchHosts(ctx context.Context, opts ...grpc.CallOption) (hostsv1.HostsService_WatchHostsClient, error) {
	return f.watchFn(ctx, opts...)
}

// --- Task 2: unit-level sink-cycle tests (fake stream, no network) ---

func TestWatch_PartialSnapshotNotRendered(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.txt")
	require.NoError(t, os.WriteFile(outPath, []byte("pre-existing"), 0o644))

	p := watchParams{
		client:          client.NewClientFromConn(nil),
		tmpl:            mustParseTestTemplate(t, `{{range .Entries}}{{.IPAddress}}{{end}}`),
		declaredVersion: contract.TemplateVersion,
		outPath:         outPath,
		statusPath:      outPath + ".status",
		health:          &sinkHealthState{},
	}

	stream := &fakeWatchStream{toRecv: []*hostsv1.WatchHostsResponse{
		entryResp("192.168.1.1", "a.local"),
		// No terminator: the stream ends (EOF) with a partial snapshot.
	}}

	result, err := runWatchRecvLoop(context.Background(), stream, p)
	require.NoError(t, err)
	assert.False(t, result.SnapshotWritten)

	data, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Equal(t, "pre-existing", string(data))
}

func TestWatch_CapExceededPreservesArtifact(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.txt")
	require.NoError(t, os.WriteFile(outPath, []byte("pre-existing"), 0o644))

	p := watchParams{
		client:          client.NewClientFromConn(nil, client.WithMaxStreamEntries(1)),
		tmpl:            mustParseTestTemplate(t, `{{.Count}}`),
		declaredVersion: contract.TemplateVersion,
		outPath:         outPath,
		statusPath:      outPath + ".status",
		health:          &sinkHealthState{},
	}

	stream := &fakeWatchStream{toRecv: []*hostsv1.WatchHostsResponse{
		entryResp("192.168.1.1", "a.local"),
		entryResp("192.168.1.2", "b.local"),
		completeResp("01CAPCHANGE", 2, contract.TemplateVersion),
	}}

	result, err := runWatchRecvLoop(context.Background(), stream, p)
	require.NoError(t, err)
	assert.False(t, result.SnapshotWritten)

	data, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Equal(t, "pre-existing", string(data))
	assert.Equal(t, 1, p.health.snapshot().ConsecutiveFailures)
}

func TestWatch_VersionMismatchPreservesArtifact(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.txt")
	require.NoError(t, os.WriteFile(outPath, []byte("pre-existing"), 0o644))

	p := watchParams{
		client:          client.NewClientFromConn(nil),
		tmpl:            mustParseTestTemplate(t, `{{.Count}}`),
		declaredVersion: contract.TemplateVersion,
		outPath:         outPath,
		statusPath:      outPath + ".status",
		health:          &sinkHealthState{},
	}

	stream := &fakeWatchStream{toRecv: []*hostsv1.WatchHostsResponse{
		completeResp("01MISMATCH", 0, "999"),
	}}

	result, err := runWatchRecvLoop(context.Background(), stream, p)
	require.NoError(t, err)
	assert.False(t, result.SnapshotWritten)

	data, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Equal(t, "pre-existing", string(data))
	assert.Equal(t, 1, p.health.snapshot().ConsecutiveFailures)
}

func TestWatch_RenderErrorPreservesArtifactAndRecordsFailure(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.txt")
	require.NoError(t, os.WriteFile(outPath, []byte("pre-existing"), 0o644))

	p := watchParams{
		client:          client.NewClientFromConn(nil),
		tmpl:            mustParseTestTemplate(t, `{{.NoSuchField}}`),
		declaredVersion: contract.TemplateVersion,
		outPath:         outPath,
		statusPath:      outPath + ".status",
		health:          &sinkHealthState{},
	}

	stream := &fakeWatchStream{toRecv: []*hostsv1.WatchHostsResponse{
		completeResp("01RENDERERR", 0, contract.TemplateVersion),
	}}

	result, err := runWatchRecvLoop(context.Background(), stream, p)
	require.NoError(t, err)
	assert.False(t, result.SnapshotWritten)

	data, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Equal(t, "pre-existing", string(data))
	assert.Equal(t, 1, p.health.snapshot().ConsecutiveFailures)
}

func TestWatch_SuccessRunsPostWriteHook(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.txt")
	markerPath := filepath.Join(dir, "hook.marker")

	p := watchParams{
		client:          client.NewClientFromConn(nil),
		tmpl:            mustParseTestTemplate(t, `{{.Count}}`),
		declaredVersion: contract.TemplateVersion,
		outPath:         outPath,
		statusPath:      outPath + ".status",
		hookCommand:     "printf ran > " + markerPath,
		hookTimeout:     time.Second,
		health:          &sinkHealthState{},
	}

	stream := &fakeWatchStream{toRecv: []*hostsv1.WatchHostsResponse{
		completeResp("01HOOKOK", 0, contract.TemplateVersion),
	}}

	result, err := runWatchRecvLoop(context.Background(), stream, p)
	require.NoError(t, err)
	assert.True(t, result.SnapshotWritten)

	data, err := os.ReadFile(markerPath)
	require.NoError(t, err)
	assert.Equal(t, "ran", string(data))

	st := p.health.snapshot()
	assert.False(t, st.ReloadFailed)
	assert.False(t, st.LastReloadSuccess.IsZero())
}

func TestWatch_HookFailureRetainsNewArtifact(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.txt")
	require.NoError(t, os.WriteFile(outPath, []byte("old-content"), 0o644))

	p := watchParams{
		client:          client.NewClientFromConn(nil),
		tmpl:            mustParseTestTemplate(t, `{{.Count}}`),
		declaredVersion: contract.TemplateVersion,
		outPath:         outPath,
		statusPath:      outPath + ".status",
		hookCommand:     "exit 1",
		hookTimeout:     time.Second,
		health:          &sinkHealthState{},
	}

	stream := &fakeWatchStream{toRecv: []*hostsv1.WatchHostsResponse{
		completeResp("01HOOKFAIL", 0, contract.TemplateVersion),
	}}

	result, err := runWatchRecvLoop(context.Background(), stream, p)
	require.NoError(t, err)
	assert.True(t, result.SnapshotWritten)

	// The artifact on disk is the NEWLY rendered content, not the old
	// content — retention, never rollback (D-12a, review H3).
	data, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Equal(t, "0", string(data))

	st := p.health.snapshot()
	assert.True(t, st.ReloadFailed)
	assert.Zero(t, st.ConsecutiveFailures)
	assert.False(t, st.LastSuccess.IsZero())
	assert.Equal(t, "01HOOKFAIL", st.RenderedChangeID)
}

func TestWatch_SkipsRedundantRenderOnSameChangeID(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.txt")
	markerPath := filepath.Join(dir, "hook.marker")

	p := watchParams{
		client:          client.NewClientFromConn(nil),
		tmpl:            mustParseTestTemplate(t, `{{.Count}}`),
		declaredVersion: contract.TemplateVersion,
		outPath:         outPath,
		statusPath:      outPath + ".status",
		hookCommand:     "printf x >> " + markerPath,
		hookTimeout:     time.Second,
		health:          &sinkHealthState{},
	}

	stream := &fakeWatchStream{toRecv: []*hostsv1.WatchHostsResponse{
		completeResp("01SAME", 0, contract.TemplateVersion),
		completeResp("01SAME", 0, contract.TemplateVersion),
	}}

	_, err := runWatchRecvLoop(context.Background(), stream, p)
	require.NoError(t, err)

	data, err := os.ReadFile(markerPath)
	require.NoError(t, err)
	assert.Equal(t, "x", string(data), "the hook must have run exactly once")
}

func TestWatch_RendersWhenArtifactMissingDespiteSameChangeID(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.txt")
	markerPath := filepath.Join(dir, "hook.marker")

	p := watchParams{
		client:          client.NewClientFromConn(nil),
		tmpl:            mustParseTestTemplate(t, `{{.Count}}`),
		declaredVersion: contract.TemplateVersion,
		outPath:         outPath,
		statusPath:      outPath + ".status",
		hookCommand:     "printf x >> " + markerPath,
		hookTimeout:     time.Second,
		health:          &sinkHealthState{},
	}

	call := 0
	stream := &fakeWatchStream{}
	stream.recvFn = func() (*hostsv1.WatchHostsResponse, error) {
		call++
		switch call {
		case 1:
			return completeResp("01SAME", 0, contract.TemplateVersion), nil
		case 2:
			require.NoError(t, os.Remove(outPath))
			return completeResp("01SAME", 0, contract.TemplateVersion), nil
		default:
			return nil, io.EOF
		}
	}

	_, err := runWatchRecvLoop(context.Background(), stream, p)
	require.NoError(t, err)

	data, err := os.ReadFile(markerPath)
	require.NoError(t, err)
	assert.Equal(t, "xx", string(data), "the hook must have run twice: the artifact was missing the second time")
}

func TestWatch_RetriesHookWhileReloadFailed(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.txt")
	markerPath := filepath.Join(dir, "hook.marker")
	sentinelPath := filepath.Join(dir, "succeed")
	// Fails until sentinelPath exists, then succeeds — lets the test flip
	// the hook from failing to succeeding without needing a second
	// watchParams (p.hookCommand is fixed for the whole session).
	hookCmd := fmt.Sprintf("printf x >> %s; test -f %s", markerPath, sentinelPath)

	p := watchParams{
		client:          client.NewClientFromConn(nil),
		tmpl:            mustParseTestTemplate(t, `{{.Count}}`),
		declaredVersion: contract.TemplateVersion,
		outPath:         outPath,
		statusPath:      outPath + ".status",
		hookCommand:     hookCmd,
		hookTimeout:     time.Second,
		health:          &sinkHealthState{},
	}

	call := 0
	stream := &fakeWatchStream{}
	stream.recvFn = func() (*hostsv1.WatchHostsResponse, error) {
		call++
		switch call {
		case 1, 2:
			return completeResp("01RETRY", 0, contract.TemplateVersion), nil
		case 3:
			require.NoError(t, os.WriteFile(sentinelPath, []byte("x"), 0o644))
			return completeResp("01RETRY", 0, contract.TemplateVersion), nil
		default:
			return nil, io.EOF
		}
	}

	_, err := runWatchRecvLoop(context.Background(), stream, p)
	require.NoError(t, err)

	// Cycle 1: renders (first time seeing 01RETRY), hook fails.
	// Cycle 2: same change ID, but reload_failed is true so the skip does
	// NOT fire — the hook is retried and fails again.
	// Cycle 3: same change ID again, still retried; the sentinel now
	// exists so the hook succeeds and reload_failed clears.
	data, err := os.ReadFile(markerPath)
	require.NoError(t, err)
	assert.Equal(t, "xxx", string(data), "the hook must have run on all three cycles while reload was failed")

	assert.False(t, p.health.snapshot().ReloadFailed)
}

// --- Task 2: goroutine-ownership / teardown tests (fake client, no network) ---

func TestWatch_StatusTickerStopsWithSession(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.txt")

	const sendDoneDelay = 200 * time.Millisecond
	fakeHosts := &fakeHostsServiceClient{
		watchFn: func(ctx context.Context, _ ...grpc.CallOption) (hostsv1.HostsService_WatchHostsClient, error) {
			return &fakeWatchStream{ctx: ctx, blockSend: true, sendDoneDelay: sendDoneDelay, blockRecvUntilDone: true}, nil
		},
	}

	p := watchParams{
		client:          &client.Client{Hosts: fakeHosts},
		tmpl:            mustParseTestTemplate(t, `{{.Count}}`),
		declaredVersion: contract.TemplateVersion,
		outPath:         outPath,
		statusPath:      outPath + ".status",
		policy:          WatchPolicy{StatusInterval: time.Millisecond}.normalized(),
		health:          &sinkHealthState{},
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := runWatch(ctx, p)
		errCh <- err
	}()

	// Give the ticker goroutine time to reach its blocked Send.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-errCh:
		elapsed := time.Since(start)
		// The ticker's Send only returns sendDoneDelay after ctx.Done()
		// fires. runWatch must wait for that (via tickerDone) before
		// returning — if it did not, it would return almost immediately
		// after cancel() instead of after sendDoneDelay has elapsed.
		assert.GreaterOrEqual(t, elapsed, sendDoneDelay,
			"runWatch returned before the ticker confirmed its own exit")
		assert.Less(t, elapsed, tickerStopBound,
			"runWatch took as long as the fallback bound — the ticker's exit was not actually observed, only waited out")
	case <-time.After(tickerStopBound + time.Second):
		t.Fatal("runWatch did not return")
	}
}

func TestWatch_ContextCancelStopsCleanly(t *testing.T) {
	setupCmdTest(t)

	dir := t.TempDir()
	tmplPath := filepath.Join(dir, "test.tmpl")
	require.NoError(t, os.WriteFile(tmplPath, []byte(testContractVersionBlock+`{{.Count}}`), 0o644))
	outPath := filepath.Join(dir, "out.txt")

	ctx, cancel := context.WithCancel(context.Background())
	errCh := startWatch(t, ctx, nil, "--template", tmplPath, "--out", outPath)

	waitForFileContent(t, outPath, "0", 2*time.Second)
	cancel()
	requireBoundedNoError(t, errCh, 2*time.Second)

	data, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Equal(t, "0", string(data))
}

// --- Task 2: CLI-level tests (bufconn, real server) ---

func TestWatch_WritesInitialArtifact(t *testing.T) {
	setupCmdTest(t)
	addHost(t, "192.168.1.10", "server.local")

	dir := t.TempDir()
	tmplPath := filepath.Join(dir, "test.tmpl")
	require.NoError(t, os.WriteFile(tmplPath,
		[]byte(testContractVersionBlock+`{{range .Entries}}{{.IPAddress}} {{.Hostname}}{{"\n"}}{{end}}`), 0o644))
	outPath := filepath.Join(dir, "out.txt")

	ctx, cancel := context.WithCancel(context.Background())
	errCh := startWatch(t, ctx, nil, "--template", tmplPath, "--out", outPath)

	waitForFileContent(t, outPath, "192.168.1.10 server.local\n", 2*time.Second)

	cancel()
	requireBoundedNoError(t, errCh, 2*time.Second)
}

func TestWatch_RewritesOnMutation(t *testing.T) {
	setupCmdTest(t)

	dir := t.TempDir()
	tmplPath := filepath.Join(dir, "test.tmpl")
	require.NoError(t, os.WriteFile(tmplPath, []byte(testContractVersionBlock+`{{.Count}}`), 0o644))
	outPath := filepath.Join(dir, "out.txt")

	ctx, cancel := context.WithCancel(context.Background())
	errCh := startWatch(t, ctx, nil, "--template", tmplPath, "--out", outPath)

	waitForFileContent(t, outPath, "0", 2*time.Second)

	addHost(t, "192.168.1.20", "mutate.local")

	waitForFileContent(t, outPath, "1", 2*time.Second)

	cancel()
	requireBoundedNoError(t, errCh, 2*time.Second)
}

func TestWatch_LoadsSidecarAtStartup(t *testing.T) {
	t.Run("artifact present, no hook runs", func(t *testing.T) {
		setupCmdTest(t)
		addHost(t, "192.168.1.10", "server.local")
		changeID := discoverChangeID(t)

		dir := t.TempDir()
		outPath := filepath.Join(dir, "out.txt")
		statusPath := outPath + ".status"
		markerPath := filepath.Join(dir, "hook.marker")

		require.NoError(t, os.WriteFile(outPath, []byte("1"), 0o644))
		require.NoError(t, writeSinkStatus(statusPath, sinkStatus{RenderedChangeID: changeID}))

		tmplPath := filepath.Join(dir, "test.tmpl")
		require.NoError(t, os.WriteFile(tmplPath, []byte(testContractVersionBlock+`{{.Count}}`), 0o644))

		ctx, cancel := context.WithCancel(context.Background())
		errCh := startWatch(t, ctx, nil,
			"--template", tmplPath, "--out", outPath, "--status-file", statusPath,
			"--exec", "printf x >> "+markerPath, "--status-interval", "10ms")

		// Give the sink's opening snapshot time to be processed.
		time.Sleep(300 * time.Millisecond)
		cancel()
		requireBoundedNoError(t, errCh, 2*time.Second)

		_, statErr := os.Stat(markerPath)
		assert.True(t, os.IsNotExist(statErr), "hook must not have run: the artifact was already current")
	})

	t.Run("artifact deleted, hook runs", func(t *testing.T) {
		setupCmdTest(t)
		addHost(t, "192.168.1.20", "server2.local")
		changeID := discoverChangeID(t)

		dir := t.TempDir()
		outPath := filepath.Join(dir, "out.txt")
		statusPath := outPath + ".status"
		markerPath := filepath.Join(dir, "hook.marker")

		// No artifact this time: deleted out of band.
		require.NoError(t, writeSinkStatus(statusPath, sinkStatus{RenderedChangeID: changeID}))

		tmplPath := filepath.Join(dir, "test.tmpl")
		require.NoError(t, os.WriteFile(tmplPath, []byte(testContractVersionBlock+`{{.Count}}`), 0o644))

		ctx, cancel := context.WithCancel(context.Background())
		errCh := startWatch(t, ctx, nil,
			"--template", tmplPath, "--out", outPath, "--status-file", statusPath,
			"--exec", "printf x >> "+markerPath)

		waitForFileContent(t, markerPath, "x", 2*time.Second)
		cancel()
		requireBoundedNoError(t, errCh, 2*time.Second)
	})
}

// --- Task 1 (review round-3 M2): status-interval flag precedence ---
//
// These live here, beside newWatchCmd, rather than in watchpolicy_test.go
// (as the pre-review plan text placed them): they exercise the "watch"
// command's own flag registration and Changed() check, which does not
// exist until this file does. Documented as a deviation in the plan
// SUMMARY.

func TestWatch_StatusIntervalDefaultsFromPolicy(t *testing.T) {
	root := NewRootCmd(WithWatchPolicy(WatchPolicy{StatusInterval: 50 * time.Millisecond}))
	watchCmd, _, err := root.Find([]string{"watch"})
	require.NoError(t, err)

	f := watchCmd.Flags().Lookup("status-interval")
	require.NotNil(t, f)
	assert.Equal(t, "50ms", f.DefValue)
}

func TestWatch_ExplicitStatusIntervalFlagOverridesPolicy(t *testing.T) {
	root := NewRootCmd(WithWatchPolicy(WatchPolicy{StatusInterval: 50 * time.Millisecond}))
	watchCmd, _, err := root.Find([]string{"watch"})
	require.NoError(t, err)

	require.NoError(t, watchCmd.ParseFlags([]string{"--status-interval=5s"}))
	assert.True(t, watchCmd.Flags().Changed("status-interval"))

	got, err := watchCmd.Flags().GetDuration("status-interval")
	require.NoError(t, err)
	assert.Equal(t, 5*time.Second, got)
}

// --- Task 3: reconnect with bounded backoff ---

// callRecorder timestamps each WatchHosts dial attempt, so a test can assert
// on the WAIT between sessions (the observable proxy for the supervising
// loop's un-exported backoff variable) rather than needing a package-level
// test seam.
type callRecorder struct {
	mu    sync.Mutex
	times []time.Time
}

func (c *callRecorder) record() {
	c.mu.Lock()
	c.times = append(c.times, time.Now())
	c.mu.Unlock()
}

func (c *callRecorder) gaps() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	gaps := make([]time.Duration, 0, len(c.times))
	for i := 1; i < len(c.times); i++ {
		gaps = append(gaps, c.times[i].Sub(c.times[i-1]))
	}
	return gaps
}

func waitForCallCount(t *testing.T, counter *int32, want int32, bound time.Duration) {
	t.Helper()
	deadline := time.Now().Add(bound)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(counter) >= want {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d WatchHosts dial attempts, got %d", want, atomic.LoadInt32(counter))
}

// alwaysFailStream returns a fakeWatchStream whose Recv always fails
// immediately (never writes an artifact) with msg.
func alwaysFailStream(ctx context.Context, msg string) *fakeWatchStream {
	return &fakeWatchStream{ctx: ctx, recvFn: func() (*hostsv1.WatchHostsResponse, error) {
		return nil, errors.New(msg)
	}}
}

func TestWatch_ReconnectsAfterStreamError(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.txt")

	var calls int32
	fakeHosts := &fakeHostsServiceClient{
		watchFn: func(ctx context.Context, _ ...grpc.CallOption) (hostsv1.HostsService_WatchHostsClient, error) {
			n := atomic.AddInt32(&calls, 1)
			if n == 1 {
				return alwaysFailStream(ctx, "connection reset"), nil
			}
			return &fakeWatchStream{ctx: ctx, toRecv: []*hostsv1.WatchHostsResponse{
				completeResp("01RECONNECT", 0, contract.TemplateVersion),
			}}, nil
		},
	}

	p := watchParams{
		client:          &client.Client{Hosts: fakeHosts},
		tmpl:            mustParseTestTemplate(t, `{{.Count}}`),
		declaredVersion: contract.TemplateVersion,
		outPath:         outPath,
		statusPath:      outPath + ".status",
		policy: WatchPolicy{
			InitialBackoff: time.Millisecond,
			MaxBackoff:     10 * time.Millisecond,
			StatusInterval: time.Second,
			Jitter:         func(d time.Duration) time.Duration { return d },
		}.normalized(),
		health: &sinkHealthState{},
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- runWatchSupervised(ctx, p)
	}()

	waitForFileContent(t, outPath, "0", 2*time.Second)
	assert.GreaterOrEqual(t, atomic.LoadInt32(&calls), int32(2))

	cancel()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("runWatchSupervised did not return")
	}
}

func TestWatch_ReconnectNoTruncation(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.txt")

	fakeHosts := &fakeHostsServiceClient{
		watchFn: func(ctx context.Context, _ ...grpc.CallOption) (hostsv1.HostsService_WatchHostsClient, error) {
			// Every dial delivers the SAME change ID: a reconnect (D-06) is
			// simply the next snapshot, and repeating the same state must
			// never touch the artifact once it is already current.
			return &fakeWatchStream{ctx: ctx, toRecv: []*hostsv1.WatchHostsResponse{
				completeResp("01SAME", 0, contract.TemplateVersion),
			}}, nil
		},
	}

	p := watchParams{
		client:          &client.Client{Hosts: fakeHosts},
		tmpl:            mustParseTestTemplate(t, `{{.Count}}`),
		declaredVersion: contract.TemplateVersion,
		outPath:         outPath,
		statusPath:      outPath + ".status",
		policy: WatchPolicy{
			InitialBackoff: time.Millisecond,
			MaxBackoff:     5 * time.Millisecond,
			StatusInterval: time.Second,
			Jitter:         func(d time.Duration) time.Duration { return d },
		}.normalized(),
		health: &sinkHealthState{},
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- runWatchSupervised(ctx, p)
	}()

	waitForFileContent(t, outPath, "0", 2*time.Second)
	before, err := os.ReadFile(outPath)
	require.NoError(t, err)

	// Let several reconnect cycles run — each after the first is a no-op
	// past the change-ID skip.
	time.Sleep(50 * time.Millisecond)

	cancel()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("runWatchSupervised did not return")
	}

	after, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Equal(t, string(before), string(after))
}

func TestWatch_BackoffResetsAfterSuccess(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.txt")

	rec := &callRecorder{}
	var calls int32
	fakeHosts := &fakeHostsServiceClient{
		watchFn: func(ctx context.Context, _ ...grpc.CallOption) (hostsv1.HostsService_WatchHostsClient, error) {
			rec.record()
			n := atomic.AddInt32(&calls, 1)
			switch n {
			case 3:
				// A session that writes a snapshot: resets the backoff for
				// the wait that follows it.
				return &fakeWatchStream{ctx: ctx, toRecv: []*hostsv1.WatchHostsResponse{
					completeResp("01RESET", 0, contract.TemplateVersion),
				}}, nil
			default:
				return alwaysFailStream(ctx, "no data"), nil
			}
		},
	}

	p := watchParams{
		client:          &client.Client{Hosts: fakeHosts},
		tmpl:            mustParseTestTemplate(t, `{{.Count}}`),
		declaredVersion: contract.TemplateVersion,
		outPath:         outPath,
		statusPath:      outPath + ".status",
		policy: WatchPolicy{
			InitialBackoff: 20 * time.Millisecond,
			MaxBackoff:     500 * time.Millisecond,
			StatusInterval: time.Second,
			Jitter:         func(d time.Duration) time.Duration { return d },
		}.normalized(),
		health: &sinkHealthState{},
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- runWatchSupervised(ctx, p)
	}()

	waitForCallCount(t, &calls, 4, 3*time.Second)
	cancel()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("runWatchSupervised did not return")
	}

	gaps := rec.gaps()
	require.GreaterOrEqual(t, len(gaps), 3)
	// gaps[0]: wait after session 1 (failed, no write) — backoff doubled
	//          from InitialBackoff.
	// gaps[1]: wait after session 2 (failed, no write) — doubled again.
	// gaps[2]: wait after session 3 (SUCCEEDED) — reset to InitialBackoff.
	assert.Greater(t, gaps[1], gaps[0]*3/2, "backoff should have doubled after the second consecutive failure")
	assert.Less(t, gaps[2], gaps[1]*3/4, "backoff should reset after a session that wrote a snapshot")
}

func TestWatch_BackoffResetsAfterSuccessfulWriteEvenIfSessionLaterFails(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.txt")

	rec := &callRecorder{}
	var calls int32
	fakeHosts := &fakeHostsServiceClient{
		watchFn: func(ctx context.Context, _ ...grpc.CallOption) (hostsv1.HostsService_WatchHostsClient, error) {
			rec.record()
			n := atomic.AddInt32(&calls, 1)
			switch n {
			case 3:
				// Writes a snapshot, THEN the stream fails — the exact case
				// an error-only return cannot express (review H5): the
				// session worked before it ended in error.
				var recvCount int32
				return &fakeWatchStream{ctx: ctx, recvFn: func() (*hostsv1.WatchHostsResponse, error) {
					c := atomic.AddInt32(&recvCount, 1)
					if c == 1 {
						return completeResp("01H5", 0, contract.TemplateVersion), nil
					}
					return nil, errors.New("stream broke after a successful write")
				}}, nil
			default:
				return alwaysFailStream(ctx, "no data"), nil
			}
		},
	}

	p := watchParams{
		client:          &client.Client{Hosts: fakeHosts},
		tmpl:            mustParseTestTemplate(t, `{{.Count}}`),
		declaredVersion: contract.TemplateVersion,
		outPath:         outPath,
		statusPath:      outPath + ".status",
		policy: WatchPolicy{
			InitialBackoff: 20 * time.Millisecond,
			MaxBackoff:     500 * time.Millisecond,
			StatusInterval: time.Second,
			Jitter:         func(d time.Duration) time.Duration { return d },
		}.normalized(),
		health: &sinkHealthState{},
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- runWatchSupervised(ctx, p)
	}()

	waitForCallCount(t, &calls, 4, 3*time.Second)
	cancel()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("runWatchSupervised did not return")
	}

	gaps := rec.gaps()
	require.GreaterOrEqual(t, len(gaps), 3)
	assert.Greater(t, gaps[1], gaps[0]*3/2, "backoff should have doubled after the second consecutive failure")
	// gaps[2] follows session 3, which wrote a snapshot and THEN failed.
	// It must be close to InitialBackoff, not a further doubling of
	// gaps[1] — the reset keys on the session RESULT, not on err == nil.
	assert.Less(t, gaps[2], gaps[1]*3/4,
		"backoff must reset after a session that wrote a snapshot, even though that session ended in error")

	data, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Equal(t, "0", string(data))
}

func TestWatch_ReconnectResetsConsecutiveFailures(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.txt")

	var calls int32
	fakeHosts := &fakeHostsServiceClient{
		watchFn: func(ctx context.Context, _ ...grpc.CallOption) (hostsv1.HostsService_WatchHostsClient, error) {
			n := atomic.AddInt32(&calls, 1)
			if n <= 2 {
				return alwaysFailStream(ctx, "disconnected"), nil
			}
			return &fakeWatchStream{ctx: ctx, toRecv: []*hostsv1.WatchHostsResponse{
				completeResp("01RECOVER", 0, contract.TemplateVersion),
			}}, nil
		},
	}

	health := &sinkHealthState{}
	p := watchParams{
		client:          &client.Client{Hosts: fakeHosts},
		tmpl:            mustParseTestTemplate(t, `{{.Count}}`),
		declaredVersion: contract.TemplateVersion,
		outPath:         outPath,
		statusPath:      outPath + ".status",
		policy: WatchPolicy{
			InitialBackoff: 5 * time.Millisecond,
			MaxBackoff:     50 * time.Millisecond,
			StatusInterval: time.Second,
			Jitter:         func(d time.Duration) time.Duration { return d },
		}.normalized(),
		health: health,
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- runWatchSupervised(ctx, p)
	}()

	waitForCallCount(t, &calls, 2, 2*time.Second)
	assert.Positive(t, health.snapshot().ConsecutiveFailures)

	waitForFileContent(t, outPath, "0", 2*time.Second)
	assert.Zero(t, health.snapshot().ConsecutiveFailures)

	cancel()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("runWatchSupervised did not return")
	}
}

func TestWatch_CancelDuringBackoffReturnsPromptly(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.txt")

	fakeHosts := &fakeHostsServiceClient{
		watchFn: func(ctx context.Context, _ ...grpc.CallOption) (hostsv1.HostsService_WatchHostsClient, error) {
			return alwaysFailStream(ctx, "always fails"), nil
		},
	}

	p := watchParams{
		client:          &client.Client{Hosts: fakeHosts},
		tmpl:            mustParseTestTemplate(t, `{{.Count}}`),
		declaredVersion: contract.TemplateVersion,
		outPath:         outPath,
		statusPath:      outPath + ".status",
		policy: WatchPolicy{
			InitialBackoff: 5 * time.Second,
			MaxBackoff:     60 * time.Second,
			StatusInterval: time.Second,
			Jitter:         func(d time.Duration) time.Duration { return d },
		}.normalized(),
		health: &sinkHealthState{},
	}

	ctx, cancel := context.WithCancel(context.Background())
	start := time.Now()
	errCh := make(chan error, 1)
	go func() {
		errCh <- runWatchSupervised(ctx, p)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-errCh:
		assert.Less(t, time.Since(start), time.Second,
			"cancel during backoff must return promptly, not after the full multi-second wait")
	case <-time.After(2 * time.Second):
		t.Fatal("runWatchSupervised did not return promptly after cancel")
	}
}
