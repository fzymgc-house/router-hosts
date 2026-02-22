package commands

import (
	"context"
	"log/slog"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
	"github.com/fzymgc-house/router-hosts/internal/client"
	"github.com/fzymgc-house/router-hosts/internal/server"
	"github.com/fzymgc-house/router-hosts/internal/storage/sqlite"
)

// setupCmdTest creates a bufconn-backed gRPC server and replaces
// newClientFromFlags so that all cobra commands connect to it.
// It restores the original newClientFromFlags and Flags on cleanup.
func setupCmdTest(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	store, err := sqlite.New("file::memory:?mode=memory&cache=shared", slog.Default())
	require.NoError(t, err)
	require.NoError(t, store.Initialize(ctx))
	t.Cleanup(func() { _ = store.Close() })

	handler := server.NewCommandHandler(store)
	hostsGen := server.NewHostsFileGenerator("/dev/null")
	svc := server.NewHostsServiceImpl(handler, store, server.WithHostsGenerator(hostsGen))

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

	// Save and restore original newClientFromFlags and Flags
	origFactory := newClientFromFlags
	origFlags := Flags
	t.Cleanup(func() {
		newClientFromFlags = origFactory
		Flags = origFlags
	})

	// Replace newClientFromFlags to return a client backed by bufconn.
	// NewClientFromConn does not take ownership of the connection,
	// so the command's defer c.Close() is a no-op.
	newClientFromFlags = func() (*client.Client, error) {
		return client.NewClientFromConn(conn), nil
	}
	Flags = GlobalFlags{}
}
