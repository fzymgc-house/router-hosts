package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"testing"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
	"github.com/fzymgc-house/router-hosts/internal/domain"
	"github.com/fzymgc-house/router-hosts/internal/storage"
	"github.com/fzymgc-house/router-hosts/internal/storage/sqlite"
)

// ---------------------------------------------------------------------------
// D-03: streaming json/csv chunk-boundary equivalence across ListPage pages
// ---------------------------------------------------------------------------

// fakeChunkCapture is a minimal exportChunkSender that records every chunk
// it is sent, used below to recompute the "expected" chunk-length sequence
// by feeding the streamed payload back through the UNCHANGED sendExportChunks
// — the same framing function the buffered "hosts" path still uses — rather
// than eyeballing exportChunkSize arithmetic (Task 1 acceptance criteria).
type fakeChunkCapture struct {
	chunks [][]byte
}

func (f *fakeChunkCapture) Send(resp *hostsv1.ExportHostsResponse) error {
	f.chunks = append(f.chunks, resp.GetChunk())
	return nil
}

// TestExportHosts_ChunkBoundaryEquivalenceAcrossPages proves the streaming
// json/csv rewrite preserves sendExportChunks' exact chunk-length sequence
// for a payload spanning multiple ListPage pages (not just multiple writer
// flushes within one page, which TestService_ExportHosts_ChunksLargePayloadJSON
// / CSV already cover with a single oversized entry). The fixture is sized
// to force at least two ListPage calls at the production exportPageSize AND
// to exceed one 64 KiB exportChunkSize window, so both boundaries are live
// simultaneously.
func TestExportHosts_ChunkBoundaryEquivalenceAcrossPages(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	origPageSize := exportPageSize
	exportPageSize = 20 // force multiple ListPage calls well before seedCount entries
	t.Cleanup(func() { exportPageSize = origPageSize })

	// Each entry carries a padded comment so both json and csv comfortably
	// exceed one 64 KiB exportChunkSize window well before seedCount entries,
	// keeping the fixture (and the AddHost seeding loop) small.
	const seedCount = 250
	comment := fmt.Sprintf("%0400d", 0) // 400 zero-padded bytes, cheap to build
	for i := 0; i < seedCount; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", (i/65536)%256, (i/256)%256, i%256)
		hostname := fmt.Sprintf("chunk-eq-host%04d.local", i)
		_, err := env.handler.AddHost(ctx, ip, hostname, &comment, nil, nil)
		require.NoError(t, err)
	}

	for _, format := range []string{"json", "csv"} {
		t.Run(format, func(t *testing.T) {
			stream, err := env.client.ExportHosts(ctx, &hostsv1.ExportHostsRequest{Format: format})
			require.NoError(t, err)
			chunks := drainExportHosts(t, stream)
			require.Greater(t, len(chunks), 1, "fixture must span more than one chunk to exercise the boundary")

			observed := make([]int, len(chunks))
			for i, c := range chunks {
				observed[i] = len(c)
			}

			data := concatChunks(chunks)
			require.Greater(t, len(data), 64*1024, "payload must exceed exportChunkSize for this test to be meaningful")

			fake := &fakeChunkCapture{}
			require.NoError(t, sendExportChunks(fake, data))
			expected := make([]int, len(fake.chunks))
			for i, c := range fake.chunks {
				expected[i] = len(c)
			}

			assert.Equal(t, expected, observed,
				"streaming chunk-length sequence must match sendExportChunks' framing of the identical concatenated payload")
		})
	}
}

// ---------------------------------------------------------------------------
// D-03: a storage failure mid-drain surfaces as a gRPC status error, not a
// partial success
// ---------------------------------------------------------------------------

// errAfterNPages wraps a real storage.Storage and fails ListPage once it has
// been called more than okPages times, simulating a storage error partway
// through a streamed export. Everything else delegates to the embedded
// store, following the mutatingListStore precedent (watch_test.go).
type errAfterNPages struct {
	storage.Storage
	okPages int
	calls   int
}

func (e *errAfterNPages) ListPage(ctx context.Context, after ulid.ULID, limit int) ([]domain.HostEntry, ulid.ULID, bool, error) {
	e.calls++
	if e.calls > e.okPages {
		return nil, ulid.ULID{}, false, fmt.Errorf("simulated storage failure on page fetch %d", e.calls)
	}
	return e.Storage.ListPage(ctx, after, limit)
}

// TestExportHosts_StorageErrorMidStreamSurfacesAsStatus proves a ListPage
// failure that happens after at least one page has already streamed
// successfully still surfaces to the client as a gRPC error, never as a
// truncated-but-apparently-complete stream (EOF with no error).
func TestExportHosts_StorageErrorMidStreamSurfacesAsStatus(t *testing.T) {
	ctx := context.Background()

	realStore, err := sqlite.New("file::memory:?mode=memory&cache=shared", slog.Default())
	require.NoError(t, err)
	require.NoError(t, realStore.Initialize(ctx))
	t.Cleanup(func() { _ = realStore.Close() })

	handler := NewCommandHandler(realStore)
	for i := 0; i < 5; i++ {
		_, addErr := handler.AddHost(ctx, fmt.Sprintf("10.0.0.%d", i), fmt.Sprintf("midstream%d.local", i), nil, nil, nil)
		require.NoError(t, addErr)
	}

	origPageSize := exportPageSize
	exportPageSize = 1 // one entry per page: guarantees the induced failure lands after page 1 has already streamed
	t.Cleanup(func() { exportPageSize = origPageSize })

	wrapped := &errAfterNPages{Storage: realStore, okPages: 1}
	svc := NewHostsServiceImpl(handler, wrapped)

	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	hostsv1.RegisterHostsServiceServer(srv, svc)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() { srv.Stop() })

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

	for _, format := range []string{"json", "csv"} {
		t.Run(format, func(t *testing.T) {
			stream, streamErr := client.ExportHosts(ctx, &hostsv1.ExportHostsRequest{Format: format})
			require.NoError(t, streamErr)

			var recvErr error
			for {
				_, recvErr = stream.Recv()
				if recvErr != nil {
					break
				}
			}
			require.Error(t, recvErr, "a mid-drain storage failure must surface as a stream error, not a clean EOF")
			assert.NotContains(t, recvErr.Error(), "EOF")
		})
	}
}
