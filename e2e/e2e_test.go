//go:build e2e

package e2e_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Category: Initial Setup
// ---------------------------------------------------------------------------

func TestE2E_InitialDeployment(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	// List hosts — should be empty
	stream, err := env.client.ListHosts(ctx, &hostsv1.ListHostsRequest{})
	require.NoError(t, err)
	entries := collectListHosts(t, stream)
	assert.Empty(t, entries, "initial list should be empty")

	// Add a host
	addResp, err := env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "192.168.1.10",
		Hostname:  "test-host.local",
		Tags:      []string{"e2e"},
	})
	require.NoError(t, err)
	assert.NotEmpty(t, addResp.GetId())
	assert.NotNil(t, addResp.GetEntry())

	// List hosts — should have one entry
	stream, err = env.client.ListHosts(ctx, &hostsv1.ListHostsRequest{})
	require.NoError(t, err)
	entries = collectListHosts(t, stream)
	require.Len(t, entries, 1)
	assert.Equal(t, "192.168.1.10", entries[0].GetIpAddress())
	assert.Equal(t, "test-host.local", entries[0].GetHostname())

	// Create a snapshot
	snapResp, err := env.client.CreateSnapshot(ctx, &hostsv1.CreateSnapshotRequest{
		Name: "initial-snapshot",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, snapResp.GetSnapshotId())
	assert.Equal(t, int32(1), snapResp.GetEntryCount())

	// List snapshots — should have one
	snapStream, err := env.client.ListSnapshots(ctx, &hostsv1.ListSnapshotsRequest{})
	require.NoError(t, err)
	snapshots := collectListSnapshots(t, snapStream)
	require.Len(t, snapshots, 1)
	assert.Equal(t, snapResp.GetSnapshotId(), snapshots[0].GetSnapshotId())
}

// ---------------------------------------------------------------------------
// Category: Daily Operations (CRUD)
// ---------------------------------------------------------------------------

func TestE2E_CRUDWorkflow(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	// Add host
	addResp, err := env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "10.0.0.1",
		Hostname:  "myhost.lan",
		Comment:   ptr("my first host"),
		Tags:      []string{"homelab"},
	})
	require.NoError(t, err)
	hostID := addResp.GetId()

	// List — verify it exists
	stream, err := env.client.ListHosts(ctx, &hostsv1.ListHostsRequest{})
	require.NoError(t, err)
	entries := collectListHosts(t, stream)
	require.Len(t, entries, 1)
	assert.Equal(t, "10.0.0.1", entries[0].GetIpAddress())

	// Update IP
	newIP := "10.0.0.2"
	updateResp, err := env.client.UpdateHost(ctx, &hostsv1.UpdateHostRequest{
		Id:              hostID,
		IpAddress:       &newIP,
		ExpectedVersion: ptr(addResp.GetEntry().GetVersion()),
	})
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.2", updateResp.GetEntry().GetIpAddress())

	// Get — verify update
	getResp, err := env.client.GetHost(ctx, &hostsv1.GetHostRequest{Id: hostID})
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.2", getResp.GetEntry().GetIpAddress())

	// Delete
	delResp, err := env.client.DeleteHost(ctx, &hostsv1.DeleteHostRequest{Id: hostID})
	require.NoError(t, err)
	assert.True(t, delResp.GetSuccess())

	// List — verify gone
	stream, err = env.client.ListHosts(ctx, &hostsv1.ListHostsRequest{})
	require.NoError(t, err)
	entries = collectListHosts(t, stream)
	assert.Empty(t, entries, "host should be deleted")
}

func TestE2E_ImportExportRoundtrip(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	hostsData := []byte(
		"192.168.1.1 gateway.local gw # Main gateway [infra]\n" +
			"192.168.1.2 webserver.local www # Web server [web,prod]\n" +
			"10.0.0.5    db.internal # Database host [db]\n",
	)

	// Import via bidi stream
	importStream, err := env.client.ImportHosts(ctx)
	require.NoError(t, err)

	format := "hosts"
	err = importStream.Send(&hostsv1.ImportHostsRequest{
		Chunk:     hostsData,
		LastChunk: true,
		Format:    &format,
	})
	require.NoError(t, err)
	err = importStream.CloseSend()
	require.NoError(t, err)

	// Collect import responses
	var finalStats *hostsv1.ImportHostsResponse
	for {
		resp, recvErr := importStream.Recv()
		if errors.Is(recvErr, io.EOF) {
			break
		}
		require.NoError(t, recvErr)
		finalStats = resp
	}
	require.NotNil(t, finalStats)
	assert.Equal(t, int32(3), finalStats.GetCreated(), "should have created 3 entries")
	assert.Equal(t, int32(0), finalStats.GetFailed(), "should have 0 failures")

	// List — verify 3 entries
	stream, err := env.client.ListHosts(ctx, &hostsv1.ListHostsRequest{})
	require.NoError(t, err)
	entries := collectListHosts(t, stream)
	require.Len(t, entries, 3)

	// Export as JSON — verify structure
	exportStream, err := env.client.ExportHosts(ctx, &hostsv1.ExportHostsRequest{Format: "json"})
	require.NoError(t, err)

	var exportBuf []byte
	for {
		resp, recvErr := exportStream.Recv()
		if errors.Is(recvErr, io.EOF) {
			break
		}
		require.NoError(t, recvErr)
		exportBuf = append(exportBuf, resp.GetChunk()...)
	}

	var exported []map[string]any
	err = json.Unmarshal(exportBuf, &exported)
	require.NoError(t, err, "exported JSON should be valid")
	assert.Len(t, exported, 3)

	// Verify one of the entries has the expected structure
	found := false
	for _, entry := range exported {
		if entry["hostname"] == "gateway.local" {
			assert.Equal(t, "192.168.1.1", entry["ip_address"])
			found = true
		}
	}
	assert.True(t, found, "gateway.local should be in exported data")
}

func TestE2E_CRUDWithAliases(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	// Add host with aliases
	addResp, err := env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "10.0.0.50",
		Hostname:  "app.example.com",
		Aliases:   []string{"api.example.com", "www.example.com"},
	})
	require.NoError(t, err)
	hostID := addResp.GetId()
	entry := addResp.GetEntry()
	assert.ElementsMatch(t, []string{"api.example.com", "www.example.com"}, entry.GetAliases())

	// List — verify aliases present
	stream, err := env.client.ListHosts(ctx, &hostsv1.ListHostsRequest{})
	require.NoError(t, err)
	entries := collectListHosts(t, stream)
	require.Len(t, entries, 1)
	assert.ElementsMatch(t, []string{"api.example.com", "www.example.com"}, entries[0].GetAliases())

	// Update aliases (add one, remove one)
	updateResp, err := env.client.UpdateHost(ctx, &hostsv1.UpdateHostRequest{
		Id: hostID,
		Aliases: &hostsv1.AliasesUpdate{
			Values: []string{"cdn.example.com", "api.example.com"},
		},
		ExpectedVersion: ptr(entry.GetVersion()),
	})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"cdn.example.com", "api.example.com"}, updateResp.GetEntry().GetAliases())

	// Clear aliases
	clearResp, err := env.client.UpdateHost(ctx, &hostsv1.UpdateHostRequest{
		Id: hostID,
		Aliases: &hostsv1.AliasesUpdate{
			Values: []string{},
		},
		ExpectedVersion: ptr(updateResp.GetEntry().GetVersion()),
	})
	require.NoError(t, err)
	assert.Empty(t, clearResp.GetEntry().GetAliases())

	// Verify via Get
	getResp, err := env.client.GetHost(ctx, &hostsv1.GetHostRequest{Id: hostID})
	require.NoError(t, err)
	assert.Empty(t, getResp.GetEntry().GetAliases())
}

func TestE2E_SearchByAlias(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	// Add hosts with aliases
	_, err := env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "10.0.0.1",
		Hostname:  "primary.example.com",
		Aliases:   []string{"alias-one.example.com"},
	})
	require.NoError(t, err)

	_, err = env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "10.0.0.2",
		Hostname:  "secondary.example.com",
		Aliases:   []string{"alias-two.example.com"},
	})
	require.NoError(t, err)

	// SearchHosts uses the Query field which matches hostname, IP, comment, and tags.
	// Search for "primary" should find only the first host.
	stream, err := env.client.SearchHosts(ctx, &hostsv1.SearchHostsRequest{
		Query: "primary",
	})
	require.NoError(t, err)
	results := collectSearchHosts(t, stream)
	require.Len(t, results, 1)
	assert.Equal(t, "primary.example.com", results[0].GetHostname())
	assert.Contains(t, results[0].GetAliases(), "alias-one.example.com")

	// Search for "example.com" should find both
	stream, err = env.client.SearchHosts(ctx, &hostsv1.SearchHostsRequest{
		Query: "example.com",
	})
	require.NoError(t, err)
	results = collectSearchHosts(t, stream)
	assert.Len(t, results, 2)
}

func TestE2E_SearchAndFilter(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	// Add hosts with different tags
	_, err := env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "10.1.0.1",
		Hostname:  "web-prod-1.example.com",
		Tags:      []string{"web", "prod"},
	})
	require.NoError(t, err)

	_, err = env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "10.1.0.2",
		Hostname:  "web-staging-1.example.com",
		Tags:      []string{"web", "staging"},
	})
	require.NoError(t, err)

	_, err = env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "10.2.0.1",
		Hostname:  "db-prod-1.example.com",
		Tags:      []string{"db", "prod"},
	})
	require.NoError(t, err)

	// Search by hostname pattern: "web" should find 2 hosts
	stream, err := env.client.SearchHosts(ctx, &hostsv1.SearchHostsRequest{
		Query: "web",
	})
	require.NoError(t, err)
	results := collectSearchHosts(t, stream)
	assert.Len(t, results, 2, "searching 'web' should match 2 hosts")

	// Search by tag: "prod" should find 2 hosts (web-prod and db-prod)
	stream, err = env.client.SearchHosts(ctx, &hostsv1.SearchHostsRequest{
		Query: "prod",
	})
	require.NoError(t, err)
	results = collectSearchHosts(t, stream)
	assert.Len(t, results, 2, "searching 'prod' should match 2 hosts")

	// Search by IP prefix: "10.2" should find the db host
	stream, err = env.client.SearchHosts(ctx, &hostsv1.SearchHostsRequest{
		Query: "10.2",
	})
	require.NoError(t, err)
	results = collectSearchHosts(t, stream)
	require.Len(t, results, 1, "searching '10.2' should match 1 host")
	assert.Equal(t, "db-prod-1.example.com", results[0].GetHostname())
}

// ---------------------------------------------------------------------------
// Category: Auth Failures
// ---------------------------------------------------------------------------

func TestE2E_WrongCARejected(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	addr := serverAddr(t, env)

	// Generate a completely separate CA and client cert signed by it
	wrongCACert, _, wrongCAKey := generateCA(t)
	wrongClientCert, wrongClientKey := generateCert(t, wrongCACert, wrongCAKey, false)

	// Use the server's real CA for root trust (so TLS handshake starts),
	// but the client cert is signed by the wrong CA — server will reject it.
	serverCACertPEM, err := os.ReadFile(env.caCertPath)
	require.NoError(t, err)

	conn := dialGRPCWithCerts(t, addr, serverCACertPEM, wrongClientCert, wrongClientKey)
	defer func() { _ = conn.Close() }()

	client := hostsv1.NewHostsServiceClient(conn)

	// The actual RPC should fail because the server rejects the unknown client cert
	_, err = client.Liveness(ctx, &hostsv1.LivenessRequest{})
	require.Error(t, err, "RPC with wrong-CA client cert should fail")
}

func TestE2E_SelfSignedClientRejected(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	addr := serverAddr(t, env)

	// Generate a self-signed client cert (acts as its own CA)
	selfSignedCA, _, selfSignedCAKey := generateCA(t)
	selfSignedClientCert, selfSignedClientKey := generateCert(t, selfSignedCA, selfSignedCAKey, false)

	// Use server's real CA for root trust (so TLS handshake can start)
	serverCACertPEM, err := os.ReadFile(env.caCertPath)
	require.NoError(t, err)

	conn := dialGRPCWithCerts(t, addr, serverCACertPEM, selfSignedClientCert, selfSignedClientKey)
	defer func() { _ = conn.Close() }()

	client := hostsv1.NewHostsServiceClient(conn)

	// The actual RPC should fail because the server requires client certs from its CA
	_, err = client.Liveness(ctx, &hostsv1.LivenessRequest{})
	require.Error(t, err, "RPC with self-signed client cert should fail")
}

// ---------------------------------------------------------------------------
// Category: Disaster Recovery
// ---------------------------------------------------------------------------

func TestE2E_SnapshotAndRollback(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	// Create initial state: 2 hosts
	_, err := env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "10.0.0.1",
		Hostname:  "host-a.local",
	})
	require.NoError(t, err)

	_, err = env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "10.0.0.2",
		Hostname:  "host-b.local",
	})
	require.NoError(t, err)

	// Create snapshot
	snapResp, err := env.client.CreateSnapshot(ctx, &hostsv1.CreateSnapshotRequest{
		Name: "before-break",
	})
	require.NoError(t, err)
	snapshotID := snapResp.GetSnapshotId()

	// "Break" state: delete host-a and add host-c
	stream, err := env.client.ListHosts(ctx, &hostsv1.ListHostsRequest{})
	require.NoError(t, err)
	allHosts := collectListHosts(t, stream)
	for _, h := range allHosts {
		if h.GetHostname() == "host-a.local" {
			_, delErr := env.client.DeleteHost(ctx, &hostsv1.DeleteHostRequest{Id: h.GetId()})
			require.NoError(t, delErr)
		}
	}

	_, err = env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "10.0.0.99",
		Hostname:  "intruder.local",
	})
	require.NoError(t, err)

	// Verify broken state: host-a gone, intruder present
	stream, err = env.client.ListHosts(ctx, &hostsv1.ListHostsRequest{})
	require.NoError(t, err)
	brokenHosts := collectListHosts(t, stream)
	hostnames := make([]string, len(brokenHosts))
	for i, h := range brokenHosts {
		hostnames[i] = h.GetHostname()
	}
	assert.NotContains(t, hostnames, "host-a.local")
	assert.Contains(t, hostnames, "intruder.local")

	// Rollback
	rollResp, err := env.client.RollbackToSnapshot(ctx, &hostsv1.RollbackToSnapshotRequest{
		SnapshotId: snapshotID,
	})
	require.NoError(t, err)
	assert.True(t, rollResp.GetSuccess())
	assert.Equal(t, int32(2), rollResp.GetRestoredEntryCount())

	// Verify restored state: host-a and host-b present, intruder gone
	stream, err = env.client.ListHosts(ctx, &hostsv1.ListHostsRequest{})
	require.NoError(t, err)
	restoredHosts := collectListHosts(t, stream)
	require.Len(t, restoredHosts, 2)

	restoredNames := make([]string, len(restoredHosts))
	for i, h := range restoredHosts {
		restoredNames[i] = h.GetHostname()
	}
	assert.Contains(t, restoredNames, "host-a.local")
	assert.Contains(t, restoredNames, "host-b.local")
	assert.NotContains(t, restoredNames, "intruder.local")
}

func TestE2E_RollbackCreatesBackup(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	// Create initial state
	_, err := env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "10.0.0.1",
		Hostname:  "original.local",
	})
	require.NoError(t, err)

	// Create snapshot
	snapResp, err := env.client.CreateSnapshot(ctx, &hostsv1.CreateSnapshotRequest{
		Name: "original-state",
	})
	require.NoError(t, err)
	snapshotID := snapResp.GetSnapshotId()

	// Modify state
	_, err = env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "10.0.0.2",
		Hostname:  "modified.local",
	})
	require.NoError(t, err)

	// List snapshots before rollback
	snapStream, err := env.client.ListSnapshots(ctx, &hostsv1.ListSnapshotsRequest{})
	require.NoError(t, err)
	snapshotsBefore := collectListSnapshots(t, snapStream)
	countBefore := len(snapshotsBefore)

	// Rollback — should create a pre-rollback backup snapshot
	rollResp, err := env.client.RollbackToSnapshot(ctx, &hostsv1.RollbackToSnapshotRequest{
		SnapshotId: snapshotID,
	})
	require.NoError(t, err)
	assert.True(t, rollResp.GetSuccess())
	backupSnapshotID := rollResp.GetNewSnapshotId()
	assert.NotEmpty(t, backupSnapshotID, "rollback should create a backup snapshot")

	// List snapshots after rollback — should have one more
	snapStream, err = env.client.ListSnapshots(ctx, &hostsv1.ListSnapshotsRequest{})
	require.NoError(t, err)
	snapshotsAfter := collectListSnapshots(t, snapStream)
	assert.Equal(t, countBefore+1, len(snapshotsAfter), "rollback should create one additional snapshot")

	// Verify the backup snapshot ID is among the listed snapshots
	backupFound := false
	for _, s := range snapshotsAfter {
		if s.GetSnapshotId() == backupSnapshotID {
			backupFound = true
			assert.Equal(t, "pre-rollback", s.GetTrigger())
			break
		}
	}
	assert.True(t, backupFound, "pre-rollback backup snapshot should exist in snapshot list")
}
