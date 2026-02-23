package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
	"github.com/fzymgc-house/router-hosts/internal/config"
	"github.com/fzymgc-house/router-hosts/internal/storage"
	"github.com/fzymgc-house/router-hosts/internal/storage/sqlite"
)

// serviceTestEnv sets up an in-process gRPC server with bufconn for service tests.
type serviceTestEnv struct {
	client  hostsv1.HostsServiceClient
	handler *CommandHandler
	store   storage.Storage
	conn    *grpc.ClientConn
}

func newServiceTestEnv(t *testing.T) *serviceTestEnv {
	t.Helper()
	ctx := context.Background()

	store, err := sqlite.New("file::memory:?mode=memory&cache=shared", slog.Default())
	require.NoError(t, err)
	require.NoError(t, store.Initialize(ctx))
	t.Cleanup(func() { _ = store.Close() })

	handler := NewCommandHandler(store)
	hostsGen := NewHostsFileGenerator("/dev/null")
	svc := NewHostsServiceImpl(handler, store, WithHostsGenerator(hostsGen))

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

	return &serviceTestEnv{
		client:  hostsv1.NewHostsServiceClient(conn),
		handler: handler,
		store:   store,
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
		if errors.Is(err, io.EOF) {
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
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		entries = append(entries, resp.Entry)
	}
	assert.Len(t, entries, 1)
	assert.Equal(t, "webserver.local", entries[0].Hostname)
}

// ---------------------------------------------------------------------------
// Import/Export Tests (Task 20)
// ---------------------------------------------------------------------------

func TestService_ImportHosts_HostsFormat(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	hostsData := "192.168.1.10\tserver.local srv.local\t# web server [web, prod]\n" +
		"10.0.0.1\tdb.local\t# database\n" +
		"# comment line\n" +
		"\n" +
		"172.16.0.1\tproxy.local\n"

	format := "hosts"
	stream, err := env.client.ImportHosts(ctx)
	require.NoError(t, err)

	err = stream.Send(&hostsv1.ImportHostsRequest{
		Chunk:     []byte(hostsData),
		LastChunk: true,
		Format:    &format,
	})
	require.NoError(t, err)
	require.NoError(t, stream.CloseSend())

	// Collect responses
	var finalResp *hostsv1.ImportHostsResponse
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		finalResp = resp
	}

	require.NotNil(t, finalResp)
	assert.Equal(t, int32(3), finalResp.Processed)
	assert.Equal(t, int32(3), finalResp.Created)
	assert.Equal(t, int32(0), finalResp.Failed)
}

func TestService_ImportHosts_SkipConflict(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	// Pre-create an entry
	_, err := env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "192.168.1.10",
		Hostname:  "server.local",
	})
	require.NoError(t, err)

	hostsData := "192.168.1.10\tserver.local\n10.0.0.1\tnew.local\n"
	format := "hosts"
	mode := "skip"

	stream, err := env.client.ImportHosts(ctx)
	require.NoError(t, err)

	err = stream.Send(&hostsv1.ImportHostsRequest{
		Chunk:        []byte(hostsData),
		LastChunk:    true,
		Format:       &format,
		ConflictMode: &mode,
	})
	require.NoError(t, err)
	require.NoError(t, stream.CloseSend())

	var finalResp *hostsv1.ImportHostsResponse
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		finalResp = resp
	}

	require.NotNil(t, finalResp)
	assert.Equal(t, int32(2), finalResp.Processed)
	assert.Equal(t, int32(1), finalResp.Created)
	assert.Equal(t, int32(1), finalResp.Skipped)
	assert.Equal(t, int32(0), finalResp.Failed)
}

func TestService_ImportHosts_ReplaceConflict(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	// Pre-create an entry
	comment := "old comment"
	_, err := env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "192.168.1.10",
		Hostname:  "server.local",
		Comment:   &comment,
	})
	require.NoError(t, err)

	hostsData := "192.168.1.10\tserver.local\t# new comment [updated]\n"
	format := "hosts"
	mode := "replace"

	stream, err := env.client.ImportHosts(ctx)
	require.NoError(t, err)

	err = stream.Send(&hostsv1.ImportHostsRequest{
		Chunk:        []byte(hostsData),
		LastChunk:    true,
		Format:       &format,
		ConflictMode: &mode,
	})
	require.NoError(t, err)
	require.NoError(t, stream.CloseSend())

	var finalResp *hostsv1.ImportHostsResponse
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		finalResp = resp
	}

	require.NotNil(t, finalResp)
	assert.Equal(t, int32(1), finalResp.Processed)
	assert.Equal(t, int32(1), finalResp.Updated)
	assert.Equal(t, int32(0), finalResp.Failed)
}

func TestService_ImportHosts_StrictConflict(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	// Pre-create an entry
	_, err := env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "192.168.1.10",
		Hostname:  "server.local",
	})
	require.NoError(t, err)

	hostsData := "192.168.1.10\tserver.local\n10.0.0.1\tnew.local\n"
	format := "hosts"
	mode := "strict"

	stream, err := env.client.ImportHosts(ctx)
	require.NoError(t, err)

	err = stream.Send(&hostsv1.ImportHostsRequest{
		Chunk:        []byte(hostsData),
		LastChunk:    true,
		Format:       &format,
		ConflictMode: &mode,
	})
	require.NoError(t, err)
	require.NoError(t, stream.CloseSend())

	var finalResp *hostsv1.ImportHostsResponse
	var recvErr error
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			recvErr = err
			break
		}
		finalResp = resp
	}

	// Strict mode now returns AlreadyExists after sending final stats.
	require.NotNil(t, finalResp)
	assert.Equal(t, int32(1), finalResp.Failed)
	assert.NotNil(t, finalResp.Error)
	assert.Contains(t, *finalResp.Error, "duplicate")
	require.Error(t, recvErr)
	assert.Contains(t, recvErr.Error(), "AlreadyExists")
}

func TestService_ExportHosts_HostsFormat(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	_, err := env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "192.168.1.10",
		Hostname:  "server.local",
		Tags:      []string{"web"},
	})
	require.NoError(t, err)

	stream, err := env.client.ExportHosts(ctx, &hostsv1.ExportHostsRequest{Format: "hosts"})
	require.NoError(t, err)

	resp, err := stream.Recv()
	require.NoError(t, err)

	content := string(resp.GetChunk())
	assert.Contains(t, content, "192.168.1.10")
	assert.Contains(t, content, "server.local")
	assert.Contains(t, content, "Generated by router-hosts")
}

func TestService_ExportHosts_JSONFormat(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	_, err := env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "10.0.0.1",
		Hostname:  "db.local",
	})
	require.NoError(t, err)

	stream, err := env.client.ExportHosts(ctx, &hostsv1.ExportHostsRequest{Format: "json"})
	require.NoError(t, err)

	resp, err := stream.Recv()
	require.NoError(t, err)

	var entries []json.RawMessage
	require.NoError(t, json.Unmarshal(resp.GetChunk(), &entries))
	assert.Len(t, entries, 1)
}

func TestService_ExportHosts_InvalidFormat(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	stream, err := env.client.ExportHosts(ctx, &hostsv1.ExportHostsRequest{Format: "xml"})
	require.NoError(t, err)

	_, err = stream.Recv()
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestService_ExportHosts_CSVFormat(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	comment := "test comment"
	_, err := env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "10.0.0.1",
		Hostname:  "db.local",
		Comment:   &comment,
		Tags:      []string{"prod"},
	})
	require.NoError(t, err)

	stream, err := env.client.ExportHosts(ctx, &hostsv1.ExportHostsRequest{Format: "csv"})
	require.NoError(t, err)

	resp, err := stream.Recv()
	require.NoError(t, err)

	content := string(resp.GetChunk())
	assert.Contains(t, content, "id,ip_address,hostname,comment,tags,aliases")
	assert.Contains(t, content, "10.0.0.1")
	assert.Contains(t, content, "db.local")
	assert.Contains(t, content, "test comment")
}

// ---------------------------------------------------------------------------
// parseHostsFormat unit tests
// ---------------------------------------------------------------------------

func TestParseHostsFormat(t *testing.T) {
	input := "192.168.1.1\thost.local alias1\t# server [web, prod]\n" +
		"# comment line\n" +
		"\n" +
		"10.0.0.1\tdb.local\n" +
		"incomplete\n"

	entries, errors := parseHostsFormat([]byte(input))

	assert.Len(t, entries, 2)
	assert.Len(t, errors, 1) // "incomplete" only has 1 field

	assert.Equal(t, "192.168.1.1", entries[0].IP)
	assert.Equal(t, "host.local", entries[0].Hostname)
	assert.Equal(t, []string{"alias1"}, entries[0].Aliases)
	require.NotNil(t, entries[0].Comment)
	assert.Equal(t, "server", *entries[0].Comment)
	assert.Equal(t, []string{"web", "prod"}, entries[0].Tags)

	assert.Equal(t, "10.0.0.1", entries[1].IP)
	assert.Equal(t, "db.local", entries[1].Hostname)
	assert.Nil(t, entries[1].Comment)
	assert.Empty(t, entries[1].Tags)
}

func TestParseHostsFormat_CommentOnly(t *testing.T) {
	input := "192.168.1.1\thost.local\t# just a comment\n"
	entries, errors := parseHostsFormat([]byte(input))
	assert.Empty(t, errors)
	require.Len(t, entries, 1)
	require.NotNil(t, entries[0].Comment)
	assert.Equal(t, "just a comment", *entries[0].Comment)
	assert.Empty(t, entries[0].Tags)
}

func TestParseHostsFormat_TagsOnly(t *testing.T) {
	input := "192.168.1.1\thost.local\t# [web, prod]\n"
	entries, errors := parseHostsFormat([]byte(input))
	assert.Empty(t, errors)
	require.Len(t, entries, 1)
	assert.Nil(t, entries[0].Comment)
	assert.Equal(t, []string{"web", "prod"}, entries[0].Tags)
}

// ---------------------------------------------------------------------------
// Snapshot Tests (Task 21)
// ---------------------------------------------------------------------------

func TestService_CreateSnapshot(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	// Add some entries first
	_, err := env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "192.168.1.10",
		Hostname:  "server.local",
	})
	require.NoError(t, err)

	resp, err := env.client.CreateSnapshot(ctx, &hostsv1.CreateSnapshotRequest{
		Name:    "test-snapshot",
		Trigger: "manual",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.GetSnapshotId())
	assert.Equal(t, int32(1), resp.GetEntryCount())
	assert.NotNil(t, resp.GetCreatedAt())
	assert.False(t, resp.GetCreatedAt().AsTime().IsZero())
}

func TestService_ListSnapshots(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	// Create two snapshots
	_, err := env.client.CreateSnapshot(ctx, &hostsv1.CreateSnapshotRequest{Name: "snap1"})
	require.NoError(t, err)
	_, err = env.client.CreateSnapshot(ctx, &hostsv1.CreateSnapshotRequest{Name: "snap2"})
	require.NoError(t, err)

	stream, err := env.client.ListSnapshots(ctx, &hostsv1.ListSnapshotsRequest{})
	require.NoError(t, err)

	var snapshots []*hostsv1.Snapshot
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		snapshots = append(snapshots, resp.GetSnapshot())
	}
	assert.Len(t, snapshots, 2)
}

func TestService_DeleteSnapshot(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	createResp, err := env.client.CreateSnapshot(ctx, &hostsv1.CreateSnapshotRequest{Name: "to-delete"})
	require.NoError(t, err)

	delResp, err := env.client.DeleteSnapshot(ctx, &hostsv1.DeleteSnapshotRequest{
		SnapshotId: createResp.GetSnapshotId(),
	})
	require.NoError(t, err)
	assert.True(t, delResp.GetSuccess())

	// Verify it's gone by listing
	stream, err := env.client.ListSnapshots(ctx, &hostsv1.ListSnapshotsRequest{})
	require.NoError(t, err)

	var snapshots []*hostsv1.Snapshot
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		snapshots = append(snapshots, resp.GetSnapshot())
	}
	assert.Empty(t, snapshots)
}

func TestService_RollbackToSnapshot(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	// Add entries and create a snapshot
	_, err := env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "192.168.1.10",
		Hostname:  "server.local",
	})
	require.NoError(t, err)

	snapResp, err := env.client.CreateSnapshot(ctx, &hostsv1.CreateSnapshotRequest{Name: "baseline"})
	require.NoError(t, err)

	// Add another entry so current state differs
	_, err = env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "10.0.0.1",
		Hostname:  "extra.local",
	})
	require.NoError(t, err)

	// Rollback
	rollResp, err := env.client.RollbackToSnapshot(ctx, &hostsv1.RollbackToSnapshotRequest{
		SnapshotId: snapResp.GetSnapshotId(),
	})
	require.NoError(t, err)
	assert.True(t, rollResp.GetSuccess())
	assert.NotEmpty(t, rollResp.GetNewSnapshotId())
	assert.Equal(t, int32(1), rollResp.GetRestoredEntryCount())

	// Verify only original entry exists
	listStream, err := env.client.ListHosts(ctx, &hostsv1.ListHostsRequest{})
	require.NoError(t, err)
	var remaining []*hostsv1.HostEntry
	for {
		resp, err := listStream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		remaining = append(remaining, resp.Entry)
	}
	assert.Len(t, remaining, 1)
	assert.Equal(t, "server.local", remaining[0].Hostname)
}

// ---------------------------------------------------------------------------
// Health Check Tests (Task 22)
// ---------------------------------------------------------------------------

func TestService_Liveness(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	resp, err := env.client.Liveness(ctx, &hostsv1.LivenessRequest{})
	require.NoError(t, err)
	assert.True(t, resp.GetAlive())
}

func TestService_Readiness_Healthy(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	resp, err := env.client.Readiness(ctx, &hostsv1.ReadinessRequest{})
	require.NoError(t, err)
	assert.True(t, resp.GetReady())
	assert.Empty(t, resp.GetReason())
}

func TestService_Readiness_Unhealthy(t *testing.T) {
	ctx := context.Background()

	// Create a store and close it to make HealthCheck fail
	store, err := sqlite.New("file::memory:?mode=memory", slog.Default())
	require.NoError(t, err)
	require.NoError(t, store.Initialize(ctx))
	handler := NewCommandHandler(store)
	svc := NewHostsServiceImpl(handler, store)
	_ = store.Close()

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
	resp, err := client.Readiness(ctx, &hostsv1.ReadinessRequest{})
	require.NoError(t, err) // gRPC call succeeds, but readiness is false
	assert.False(t, resp.GetReady())
	assert.NotEmpty(t, resp.GetReason())
}

func TestService_Health_DetailedStatus(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	resp, err := env.client.Health(ctx, &hostsv1.HealthRequest{})
	require.NoError(t, err)
	assert.True(t, resp.GetHealthy())

	// Server info
	require.NotNil(t, resp.GetServer())
	assert.Equal(t, "dev", resp.GetServer().GetVersion())
	assert.GreaterOrEqual(t, resp.GetServer().GetUptimeSeconds(), int64(0))

	// Database
	require.NotNil(t, resp.GetDatabase())
	assert.True(t, resp.GetDatabase().GetConnected())
	assert.Equal(t, "sqlite", resp.GetDatabase().GetBackend())
	assert.GreaterOrEqual(t, resp.GetDatabase().GetLatencyMs(), int64(0))

	// ACME (disabled)
	require.NotNil(t, resp.GetAcme())
	assert.False(t, resp.GetAcme().GetEnabled())
	assert.Equal(t, "disabled", resp.GetAcme().GetStatus())

	// Hooks (none configured in test)
	require.NotNil(t, resp.GetHooks())
	assert.Equal(t, int32(0), resp.GetHooks().GetConfiguredCount())
}

func TestService_Health_WithHooks(t *testing.T) {
	ctx := context.Background()

	store, err := sqlite.New("file::memory:?mode=memory&cache=shared", slog.Default())
	require.NoError(t, err)
	require.NoError(t, store.Initialize(ctx))
	t.Cleanup(func() { _ = store.Close() })

	handler := NewCommandHandler(store)
	hooks := NewHookExecutor(
		[]config.HookDefinition{{Name: "on-success", Command: "echo ok"}},
		[]config.HookDefinition{{Name: "on-failure", Command: "echo fail"}},
		5*time.Second,
		slog.Default(),
	)
	svc := NewHostsServiceImpl(handler, store, WithHookExecutor(hooks))

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
	resp, err := client.Health(ctx, &hostsv1.HealthRequest{})
	require.NoError(t, err)
	assert.True(t, resp.GetHealthy())

	require.NotNil(t, resp.GetHooks())
	assert.Equal(t, int32(2), resp.GetHooks().GetConfiguredCount())
	assert.ElementsMatch(t, []string{"on-success", "on-failure"}, resp.GetHooks().GetHookNames())
}

// TestService_Health_WithVersion verifies that WithVersion properly injects
// version and build info into the Health RPC response (Finding 133.146).
func TestService_Health_WithVersion(t *testing.T) {
	ctx := context.Background()

	store, err := sqlite.New("file::memory:?mode=memory&cache=shared", slog.Default())
	require.NoError(t, err)
	require.NoError(t, store.Initialize(ctx))
	t.Cleanup(func() { _ = store.Close() })

	handler := NewCommandHandler(store)
	svc := NewHostsServiceImpl(handler, store, WithVersion("v1.2.3", "abc1234"))

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
	resp, err := client.Health(ctx, &hostsv1.HealthRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp.GetServer())
	assert.Equal(t, "v1.2.3", resp.GetServer().GetVersion())
	assert.Equal(t, "abc1234", resp.GetServer().GetBuildInfo())
}

func TestService_UpdateHost_AllFields(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	comment := "original"
	addResp, err := env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "192.168.1.1",
		Hostname:  "host.local",
		Comment:   &comment,
		Tags:      []string{"old"},
		Aliases:   []string{"h.local"},
	})
	require.NoError(t, err)

	newIP := "10.0.0.99"
	newHostname := "newhost.local"
	newComment := "updated"
	version := "1"
	updateResp, err := env.client.UpdateHost(ctx, &hostsv1.UpdateHostRequest{
		Id:              addResp.Id,
		IpAddress:       &newIP,
		Hostname:        &newHostname,
		Comment:         &newComment,
		Aliases:         &hostsv1.AliasesUpdate{Values: []string{"nh.local"}},
		Tags:            &hostsv1.TagsUpdate{Values: []string{"new"}},
		ExpectedVersion: &version,
	})
	require.NoError(t, err)
	require.NotNil(t, updateResp.Entry)
	assert.Equal(t, "10.0.0.99", updateResp.Entry.IpAddress)
	assert.Equal(t, "newhost.local", updateResp.Entry.Hostname)
	assert.Equal(t, "updated", updateResp.Entry.GetComment())
	assert.Equal(t, []string{"nh.local"}, updateResp.Entry.Aliases)
	assert.Equal(t, []string{"new"}, updateResp.Entry.Tags)
}

func TestService_UpdateHost_InvalidID(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	newIP := "10.0.0.1"
	_, err := env.client.UpdateHost(ctx, &hostsv1.UpdateHostRequest{
		Id:        "not-a-ulid",
		IpAddress: &newIP,
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestService_UpdateHost_InvalidExpectedVersion(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	badVersion := "not-a-number"
	_, err := env.client.UpdateHost(ctx, &hostsv1.UpdateHostRequest{
		Id:              "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		ExpectedVersion: &badVersion,
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestService_DeleteHost_InvalidID(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	_, err := env.client.DeleteHost(ctx, &hostsv1.DeleteHostRequest{Id: "not-a-ulid"})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestService_DeleteHost_NotFound(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	_, err := env.client.DeleteHost(ctx, &hostsv1.DeleteHostRequest{Id: "01ARZ3NDEKTSV4RRFFQ69G5FAV"})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestService_UpdateHost_NotFound(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	newIP := "10.0.0.1"
	version := "1"
	_, err := env.client.UpdateHost(ctx, &hostsv1.UpdateHostRequest{
		Id:              "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		IpAddress:       &newIP,
		ExpectedVersion: &version,
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestService_ListSnapshots_WithLimit(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	// Create three snapshots
	for i := range 3 {
		_, err := env.client.CreateSnapshot(ctx, &hostsv1.CreateSnapshotRequest{
			Name: fmt.Sprintf("snap-%d", i),
		})
		require.NoError(t, err)
	}

	stream, err := env.client.ListSnapshots(ctx, &hostsv1.ListSnapshotsRequest{
		Limit:  2,
		Offset: 1,
	})
	require.NoError(t, err)

	var snapshots []*hostsv1.Snapshot
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		snapshots = append(snapshots, resp.GetSnapshot())
	}
	assert.Len(t, snapshots, 2)
}

// TestService_CreateSnapshot_RetentionEnforced verifies that when
// WithRetentionConfig is wired into the service, creating snapshots beyond the
// configured maximum causes the oldest snapshots to be pruned automatically
// (Finding 133.147).
func TestService_CreateSnapshot_RetentionEnforced(t *testing.T) {
	ctx := context.Background()

	store, err := sqlite.New("file::memory:?mode=memory&cache=shared", slog.Default())
	require.NoError(t, err)
	require.NoError(t, store.Initialize(ctx))
	t.Cleanup(func() { _ = store.Close() })

	handler := NewCommandHandler(store)
	hostsGen := NewHostsFileGenerator("/dev/null")
	maxSnaps := 2
	svc := NewHostsServiceImpl(handler, store,
		WithHostsGenerator(hostsGen),
		WithRetentionConfig(&maxSnaps, nil),
	)

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

	// Add a host entry so snapshots are non-trivial.
	_, err = client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "192.168.1.1",
		Hostname:  "retention-test.local",
	})
	require.NoError(t, err)

	// Create 3 snapshots; with maxSnaps=2 the oldest should be pruned after
	// each CreateSnapshot call that exceeds the limit.
	for i := range 3 {
		_, err = client.CreateSnapshot(ctx, &hostsv1.CreateSnapshotRequest{
			Name:    fmt.Sprintf("snap-%d", i),
			Trigger: "manual",
		})
		require.NoError(t, err)
	}

	// List all remaining snapshots.
	stream, err := client.ListSnapshots(ctx, &hostsv1.ListSnapshotsRequest{})
	require.NoError(t, err)

	var snapshots []*hostsv1.Snapshot
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		snapshots = append(snapshots, resp.GetSnapshot())
	}

	assert.Len(t, snapshots, 2, "retention policy must prune oldest snapshot, leaving only 2")
}

func TestService_RollbackToSnapshot_NotFound(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	_, err := env.client.RollbackToSnapshot(ctx, &hostsv1.RollbackToSnapshotRequest{
		SnapshotId: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// TestService_RollbackToSnapshot_Atomicity verifies that all entries added after
// a snapshot are removed when rolling back, and only the snapshotted entries
// remain (Finding 133.46).
func TestService_RollbackToSnapshot_Atomicity(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	// Add a baseline host entry.
	baseResp, err := env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "192.168.1.1",
		Hostname:  "base.local",
	})
	require.NoError(t, err)

	// Snapshot the current state (1 entry).
	snapResp, err := env.client.CreateSnapshot(ctx, &hostsv1.CreateSnapshotRequest{
		Name:    "atomicity-test",
		Trigger: "manual",
	})
	require.NoError(t, err)
	require.Equal(t, int32(1), snapResp.GetEntryCount())

	// Add two more entries after the snapshot.
	for i, ip := range []string{"10.0.0.1", "10.0.0.2"} {
		_, err = env.client.AddHost(ctx, &hostsv1.AddHostRequest{
			IpAddress: ip,
			Hostname:  fmt.Sprintf("extra%d.local", i),
		})
		require.NoError(t, err)
	}

	// Confirm 3 entries exist before rollback.
	stream, err := env.client.ListHosts(ctx, &hostsv1.ListHostsRequest{})
	require.NoError(t, err)
	var before []*hostsv1.HostEntry
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		before = append(before, resp.Entry)
	}
	require.Len(t, before, 3)

	// Roll back to the snapshot.
	rollResp, err := env.client.RollbackToSnapshot(ctx, &hostsv1.RollbackToSnapshotRequest{
		SnapshotId: snapResp.GetSnapshotId(),
	})
	require.NoError(t, err)
	require.True(t, rollResp.GetSuccess())
	require.Equal(t, int32(1), rollResp.GetRestoredEntryCount())

	// Only the baseline entry must remain.
	listStream, err := env.client.ListHosts(ctx, &hostsv1.ListHostsRequest{})
	require.NoError(t, err)
	var after []*hostsv1.HostEntry
	for {
		resp, err := listStream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		after = append(after, resp.Entry)
	}
	require.Len(t, after, 1, "rollback must atomically remove all post-snapshot entries")
	assert.Equal(t, "base.local", after[0].Hostname)
	assert.Equal(t, "192.168.1.1", after[0].IpAddress)
	// The restored entry gets a new ID since rollback re-imports from snapshot data.
	assert.NotEmpty(t, after[0].Id)
	_ = baseResp
}

// TestService_ImportHosts_MultiChunk verifies that an import stream whose data
// arrives in multiple separate chunks correctly imports all entries and returns
// accurate progress stats (Finding 133.51).
func TestService_ImportHosts_MultiChunk(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	// Split the hosts data across three chunks — none marked last except the final.
	chunks := []string{
		"192.168.1.10\tserver.local\t# web server [web]\n",
		"10.0.0.1\tdb.local\t# database [db]\n",
		"172.16.0.1\tproxy.local\n",
	}

	format := "hosts"
	stream, err := env.client.ImportHosts(ctx)
	require.NoError(t, err)

	for i, chunk := range chunks {
		isLast := i == len(chunks)-1
		req := &hostsv1.ImportHostsRequest{
			Chunk:     []byte(chunk),
			LastChunk: isLast,
		}
		if i == 0 {
			req.Format = &format
		}
		require.NoError(t, stream.Send(req))
	}
	require.NoError(t, stream.CloseSend())

	// Collect all responses; the final one carries cumulative stats.
	var finalResp *hostsv1.ImportHostsResponse
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		finalResp = resp
	}

	require.NotNil(t, finalResp)
	assert.Equal(t, int32(3), finalResp.Processed, "all 3 entries across chunks must be processed")
	assert.Equal(t, int32(3), finalResp.Created, "all 3 entries must be created")
	assert.Equal(t, int32(0), finalResp.Failed)

	// Verify all three entries are actually present in storage.
	listStream, err := env.client.ListHosts(ctx, &hostsv1.ListHostsRequest{})
	require.NoError(t, err)
	var entries []*hostsv1.HostEntry
	for {
		resp, err := listStream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		entries = append(entries, resp.Entry)
	}
	assert.Len(t, entries, 3)
}

// TestService_ImportHosts_MaxSizeExceeded verifies that sending a payload
// larger than maxImportBytes (64 MiB) returns codes.ResourceExhausted.
func TestService_ImportHosts_MaxSizeExceeded(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	stream, err := env.client.ImportHosts(ctx)
	require.NoError(t, err)

	// Build a chunk just over the limit. We use a repeated single byte to
	// keep memory allocation predictable in tests.
	oversize := bytes.Repeat([]byte("x"), maxImportBytes+1)
	format := "hosts"
	err = stream.Send(&hostsv1.ImportHostsRequest{
		Chunk:     oversize,
		LastChunk: true,
		Format:    &format,
	})
	// Send may succeed locally (buffered); the error surfaces on Recv.
	if err != nil {
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.ResourceExhausted, st.Code())
		return
	}
	require.NoError(t, stream.CloseSend())

	var recvErr error
	for {
		_, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			recvErr = err
			break
		}
	}

	require.Error(t, recvErr)
	st, ok := status.FromError(recvErr)
	require.True(t, ok)
	assert.Equal(t, codes.ResourceExhausted, st.Code())
}

// TestService_ImportHosts_UnsupportedFormat verifies that requesting an
// unsupported format (e.g. "csv") returns codes.InvalidArgument.
func TestService_ImportHosts_UnsupportedFormat(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	stream, err := env.client.ImportHosts(ctx)
	require.NoError(t, err)

	format := "csv"
	err = stream.Send(&hostsv1.ImportHostsRequest{
		Chunk:     []byte("192.168.1.1,host.local\n"),
		LastChunk: true,
		Format:    &format,
	})
	require.NoError(t, err)
	require.NoError(t, stream.CloseSend())

	var recvErr error
	for {
		_, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			recvErr = err
			break
		}
	}

	require.Error(t, recvErr)
	st, ok := status.FromError(recvErr)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "csv")
}

// TestService_ImportHosts_InvalidConflictMode verifies that an unrecognised
// conflict_mode value returns codes.InvalidArgument.
func TestService_ImportHosts_InvalidConflictMode(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	stream, err := env.client.ImportHosts(ctx)
	require.NoError(t, err)

	format := "hosts"
	mode := "overwrite"
	err = stream.Send(&hostsv1.ImportHostsRequest{
		Chunk:        []byte("192.168.1.1\thost.local\n"),
		LastChunk:    true,
		Format:       &format,
		ConflictMode: &mode,
	})
	require.NoError(t, err)
	require.NoError(t, stream.CloseSend())

	var recvErr error
	for {
		_, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			recvErr = err
			break
		}
	}

	require.Error(t, recvErr)
	st, ok := status.FromError(recvErr)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "overwrite")
}

func TestService_UpdateHost_AliasesNilValues(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	addResp, err := env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "192.168.1.1",
		Hostname:  "host.local",
		Aliases:   []string{"a.local"},
	})
	require.NoError(t, err)

	// Send an AliasesUpdate with nil Values to clear aliases
	version := "1"
	updateResp, err := env.client.UpdateHost(ctx, &hostsv1.UpdateHostRequest{
		Id:              addResp.Id,
		Aliases:         &hostsv1.AliasesUpdate{Values: nil},
		Tags:            &hostsv1.TagsUpdate{Values: nil},
		ExpectedVersion: &version,
	})
	require.NoError(t, err)
	require.NotNil(t, updateResp.Entry)
	assert.Empty(t, updateResp.Entry.Aliases)
	assert.Empty(t, updateResp.Entry.Tags)
}

// TestService_UpdateHost_AliasMatchesHostname verifies that updating a host's
// aliases to include the host's own hostname is rejected with InvalidArgument.
// Validation rejects aliases that duplicate the primary hostname.
func TestService_UpdateHost_AliasMatchesHostname(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()

	addResp, err := env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "10.0.0.50",
		Hostname:  "target.local",
	})
	require.NoError(t, err)

	version := "1"
	_, err = env.client.UpdateHost(ctx, &hostsv1.UpdateHostRequest{
		Id: addResp.Id,
		// Setting an alias that matches the primary hostname is invalid.
		Aliases:         &hostsv1.AliasesUpdate{Values: []string{"target.local"}},
		ExpectedVersion: &version,
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}
