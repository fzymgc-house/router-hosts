package server

import (
	"context"
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
	"github.com/fzymgc-house/router-hosts/internal/storage/sqlite"
)

// serviceTestEnv sets up an in-process gRPC server with bufconn for service tests.
type serviceTestEnv struct {
	client  hostsv1.HostsServiceClient
	handler *CommandHandler
	conn    *grpc.ClientConn
}

func newServiceTestEnv(t *testing.T) *serviceTestEnv {
	t.Helper()
	ctx := context.Background()

	store, err := sqlite.New("file::memory:?mode=memory&cache=shared", slog.Default())
	require.NoError(t, err)
	require.NoError(t, store.Initialize(ctx))
	t.Cleanup(func() { store.Close() })

	handler := NewCommandHandler(store)
	svc := NewHostsServiceImpl(handler)

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
	t.Cleanup(func() { conn.Close() })

	return &serviceTestEnv{
		client:  hostsv1.NewHostsServiceClient(conn),
		handler: handler,
		conn:    conn,
	}
}

func TestService_AddHost_HappyPath(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	comment := "test comment"
	resp, err := env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "192.168.1.10",
		Hostname:  "server.local",
		Comment:   &comment,
		Tags:      []string{"web"},
		Aliases:   []string{"srv.local"},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.Id)
	require.NotNil(t, resp.Entry)
	assert.Equal(t, "192.168.1.10", resp.Entry.IpAddress)
	assert.Equal(t, "server.local", resp.Entry.Hostname)
	assert.Equal(t, "test comment", resp.Entry.GetComment())
	assert.Equal(t, []string{"web"}, resp.Entry.Tags)
	assert.Equal(t, []string{"srv.local"}, resp.Entry.Aliases)
	assert.Equal(t, "1", resp.Entry.Version)
	assert.NotNil(t, resp.Entry.CreatedAt)
	assert.NotNil(t, resp.Entry.UpdatedAt)
}

func TestService_AddHost_Duplicate(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	req := &hostsv1.AddHostRequest{
		IpAddress: "192.168.1.10",
		Hostname:  "server.local",
	}
	_, err := env.client.AddHost(ctx, req)
	require.NoError(t, err)

	_, err = env.client.AddHost(ctx, req)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.AlreadyExists, st.Code())
}

func TestService_GetHost_Found(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	addResp, err := env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "10.0.0.1",
		Hostname:  "db.local",
		Tags:      []string{"prod"},
	})
	require.NoError(t, err)

	getResp, err := env.client.GetHost(ctx, &hostsv1.GetHostRequest{Id: addResp.Id})
	require.NoError(t, err)
	require.NotNil(t, getResp.Entry)
	assert.Equal(t, addResp.Id, getResp.Entry.Id)
	assert.Equal(t, "10.0.0.1", getResp.Entry.IpAddress)
	assert.Equal(t, "db.local", getResp.Entry.Hostname)
}

func TestService_GetHost_NotFound(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	_, err := env.client.GetHost(ctx, &hostsv1.GetHostRequest{Id: "01ARZ3NDEKTSV4RRFFQ69G5FAV"})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestService_GetHost_InvalidID(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	_, err := env.client.GetHost(ctx, &hostsv1.GetHostRequest{Id: "not-a-ulid"})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestService_UpdateHost_IPChange(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	addResp, err := env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "192.168.1.1",
		Hostname:  "host.local",
	})
	require.NoError(t, err)

	newIP := "10.0.0.99"
	version := "1"
	updateResp, err := env.client.UpdateHost(ctx, &hostsv1.UpdateHostRequest{
		Id:              addResp.Id,
		IpAddress:       &newIP,
		ExpectedVersion: &version,
	})
	require.NoError(t, err)
	require.NotNil(t, updateResp.Entry)
	assert.Equal(t, "10.0.0.99", updateResp.Entry.IpAddress)
	assert.Equal(t, "2", updateResp.Entry.Version)
}

func TestService_UpdateHost_VersionConflict(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	addResp, err := env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "192.168.1.1",
		Hostname:  "host.local",
	})
	require.NoError(t, err)

	newIP := "10.0.0.99"
	wrongVersion := "99"
	_, err = env.client.UpdateHost(ctx, &hostsv1.UpdateHostRequest{
		Id:              addResp.Id,
		IpAddress:       &newIP,
		ExpectedVersion: &wrongVersion,
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Aborted, st.Code())
}

func TestService_DeleteHost(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	addResp, err := env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "192.168.1.1",
		Hostname:  "host.local",
	})
	require.NoError(t, err)

	delResp, err := env.client.DeleteHost(ctx, &hostsv1.DeleteHostRequest{Id: addResp.Id})
	require.NoError(t, err)
	assert.True(t, delResp.Success)

	// Verify it's gone
	_, err = env.client.GetHost(ctx, &hostsv1.GetHostRequest{Id: addResp.Id})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestService_ListHosts(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	// Add 3 entries
	for i, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		_, err := env.client.AddHost(ctx, &hostsv1.AddHostRequest{
			IpAddress: ip,
			Hostname:  "host" + string(rune('a'+i)) + ".local",
		})
		require.NoError(t, err)
	}

	stream, err := env.client.ListHosts(ctx, &hostsv1.ListHostsRequest{})
	require.NoError(t, err)

	var entries []*hostsv1.HostEntry
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		entries = append(entries, resp.Entry)
	}
	assert.Len(t, entries, 3)
}

func TestService_SearchHosts(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	_, err := env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "192.168.1.10",
		Hostname:  "webserver.local",
		Tags:      []string{"web"},
	})
	require.NoError(t, err)

	_, err = env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "192.168.1.20",
		Hostname:  "dbserver.local",
		Tags:      []string{"db"},
	})
	require.NoError(t, err)

	stream, err := env.client.SearchHosts(ctx, &hostsv1.SearchHostsRequest{
		Query: "webserver",
	})
	require.NoError(t, err)

	var entries []*hostsv1.HostEntry
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		entries = append(entries, resp.Entry)
	}
	assert.Len(t, entries, 1)
	assert.Equal(t, "webserver.local", entries[0].Hostname)
}
