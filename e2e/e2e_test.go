//go:build e2e

package e2e_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
	"github.com/fzymgc-house/router-hosts/internal/client/commands"
	"github.com/fzymgc-house/router-hosts/internal/contract"
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

// ---------------------------------------------------------------------------
// Category: Watch Sink over real mTLS
// ---------------------------------------------------------------------------
//
// Every prior E2E test in this file drives HostsService over the harness's
// real, CA-verified mTLS connection but never exercises WatchHosts. These
// four close that gap (01-VALIDATION.md's Wave 0 requirement, review M3/M4):
// the common-name extraction, its keying into a real SinkHealth registry,
// the concurrent bidi stream, the change ID, and the reconnect supervisor
// are all proven here against a connection that is genuinely torn down and
// restored — not merely a cancelled RPC on a live grpc.ClientConn.

// sidecarStatus mirrors the JSON shape internal/client/commands.sinkStatus
// writes (that type is unexported, and e2e is an external test package, so
// this local mirror is how the restart test reads the sidecar without
// reaching into the commands package's internals).
type sidecarStatus struct {
	ConsecutiveFailures int `json:"consecutive_failures"`
}

func readSidecarConsecutiveFailures(t *testing.T, path string) (int, bool) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	var st sidecarStatus
	if err := json.Unmarshal(data, &st); err != nil {
		return 0, false
	}
	return st.ConsecutiveFailures, true
}

func TestE2E_WatchSnapshotOverMTLS(t *testing.T) {
	env := setupTestEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, err := env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "10.10.0.1",
		Hostname:  "watch-a.local",
	})
	require.NoError(t, err)
	_, err = env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "10.10.0.2",
		Hostname:  "watch-b.local",
	})
	require.NoError(t, err)

	expectedChangeID, err := env.store.LatestEventID(ctx)
	require.NoError(t, err)

	stream, err := env.client.WatchHosts(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&hostsv1.WatchHostsRequest{Follow: false}))
	require.NoError(t, stream.CloseSend())

	entries, complete := collectWatchSnapshot(t, stream)
	require.NotNil(t, complete, "expected a snapshot terminator")
	require.Len(t, entries, 2)
	assert.Equal(t, int32(2), complete.GetCount())
	assert.Equal(t, contract.TemplateVersion, complete.GetContractVersion())
	assert.Equal(t, expectedChangeID.String(), complete.GetChangeId())

	// A second Watch with no mutation in between must return the same
	// change ID (D-19), now proven over a real mTLS connection.
	stream2, err := env.client.WatchHosts(ctx)
	require.NoError(t, err)
	require.NoError(t, stream2.Send(&hostsv1.WatchHostsRequest{Follow: false}))
	require.NoError(t, stream2.CloseSend())

	_, complete2 := collectWatchSnapshot(t, stream2)
	require.NotNil(t, complete2)
	assert.Equal(t, complete.GetChangeId(), complete2.GetChangeId())
}

func TestE2E_WatchPushesOnMutation(t *testing.T) {
	env := setupTestEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	stream, err := env.client.WatchHosts(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&hostsv1.WatchHostsRequest{Follow: true}))

	_, initial := collectWatchSnapshot(t, stream)
	require.NotNil(t, initial, "expected an initial snapshot on connect")

	// A client status message on the same follow stream must be accepted
	// without disturbing snapshot delivery — the concurrent send-while-
	// receiving path, exercised here over a real connection.
	require.NoError(t, stream.Send(&hostsv1.WatchHostsRequest{
		Status: &hostsv1.SinkStatus{ContractVersion: contract.TemplateVersion},
	}))

	_, err = env.client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "10.20.0.1",
		Hostname:  "pushed.local",
	})
	require.NoError(t, err)

	// Recv blocks on the bounded ctx above, so a regression here fails
	// loudly instead of hanging the suite.
	entries, complete := collectWatchSnapshot(t, stream)
	require.NotNil(t, complete, "expected a further snapshot after the mutation")

	found := false
	for _, e := range entries {
		if e.GetHostname() == "pushed.local" {
			found = true
		}
	}
	assert.True(t, found, "pushed host should appear in the follow-mode snapshot")
}

func TestE2E_WatchSinkHealthKeyedByCN(t *testing.T) {
	env := setupTestEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	stream, err := env.client.WatchHosts(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&hostsv1.WatchHostsRequest{Follow: true}))

	_, initial := collectWatchSnapshot(t, stream)
	require.NotNil(t, initial)

	require.NoError(t, stream.Send(&hostsv1.WatchHostsRequest{
		Status: &hostsv1.SinkStatus{
			ConsecutiveFailures: 3,
			ContractVersion:     contract.TemplateVersion,
			RenderedChangeId:    initial.GetChangeId(),
		},
	}))

	var found bool
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		snap := env.sinkHealth.Snapshot()
		if st, ok := snap.States["e2e-test-client"]; ok {
			// Assert the literal CN, not "some non-empty key" — the literal
			// is what proves extraction reached
			// VerifiedChains[0][0].Subject.CommonName rather than anything
			// else.
			assert.Equal(t, int64(3), st.ConsecutiveFailures)
			assert.Equal(t, contract.TemplateVersion, st.ContractVersion)
			assert.Equal(t, initial.GetChangeId(), st.RenderedChangeID)

			assert.Len(t, snap.States, 1, "registry should hold exactly one key")
			_, hasEmptyKey := snap.States[""]
			assert.False(t, hasEmptyKey, "registry must not hold an entry under the empty key")

			found = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.True(t, found, "sink health registry should hold an entry keyed by e2e-test-client")
}

func TestE2E_WatchSinkSurvivesServerRestart(t *testing.T) {
	env := setupTestEnv(t)

	dir := t.TempDir()
	templatePath := filepath.Join(dir, "hosts.tmpl")
	outPath := filepath.Join(dir, "hosts.out")
	statusPath := filepath.Join(dir, "hosts.out.status")

	tmplSrc := "{{define \"contract_version\"}}1{{end -}}\n" +
		"{{range .Entries}}{{.IPAddress}} {{.Hostname}}\n{{end -}}"
	require.NoError(t, os.WriteFile(templatePath, []byte(tmplSrc), 0o600))

	// Seed one host before the sink ever connects, so its initial render is
	// non-empty and step 1's byte comparison below is meaningful — an empty
	// artifact would make "byte-identical during the outage" vacuously true.
	_, err := env.client.AddHost(context.Background(), &hostsv1.AddHostRequest{
		IpAddress: "10.29.0.1",
		Hostname:  "seed.local",
	})
	require.NoError(t, err)

	// The only supported way to shorten the sink's backoff from this
	// external test package: e2e is `package e2e_test`, so unexported
	// package-level variables in internal/client/commands are not merely
	// inadvisable to reach for, they are unreachable and referencing them
	// would not compile (review H4). The identity Jitter keeps the
	// reconnect timing deterministic.
	rootCmd := commands.NewRootCmd(commands.WithWatchPolicy(commands.WatchPolicy{
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     100 * time.Millisecond,
		StatusInterval: 50 * time.Millisecond,
		Jitter:         func(d time.Duration) time.Duration { return d },
	}))
	rootCmd.SetArgs([]string{
		"watch",
		"--server", env.addr,
		"--cert", env.clientCertPath,
		"--key", env.clientKeyPath,
		"--ca", env.caCertPath,
		"--template", templatePath,
		"--out", outPath,
		"--status-file", statusPath,
	})

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- rootCmd.ExecuteContext(runCtx)
	}()

	// 1. Wait for the artifact to appear and record its bytes.
	var initialBytes []byte
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		b, readErr := os.ReadFile(outPath)
		if readErr == nil {
			initialBytes = b
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	require.NotEmpty(t, initialBytes, "sink should have written an initial artifact")

	// 2. Stop the server and return — the server is now down and stays
	// down. No wait-for-readiness here: that is exactly what would remove
	// the outage window step 3 asserts against (reviews M4, M10).
	stopServer(t, env)

	// 3. While it is down, the artifact stays byte-identical and the
	// sidecar's failure count rises.
	time.Sleep(300 * time.Millisecond)
	stillBytes, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Equal(t, initialBytes, stillBytes, "artifact must stay byte-identical during the outage")

	var sawFailure bool
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if n, ok := readSidecarConsecutiveFailures(t, statusPath); ok && n > 0 {
			sawFailure = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	require.True(t, sawFailure, "sidecar should report a rising failure count during the outage")

	// 4. Restart on the same address, then mutate over a fresh RPC so the
	// post-reconnect snapshot carries genuinely new content — asserting a
	// rewrite against unchanged state would instead exercise the change-ID
	// skip and prove nothing about reconnection.
	startServer(t, env)
	_, err = env.client.AddHost(context.Background(), &hostsv1.AddHostRequest{
		IpAddress: "10.30.0.1",
		Hostname:  "restarted.local",
	})
	require.NoError(t, err)

	// 5. The sink reconnects on its own, rewrites the artifact, and its
	// failure count returns to zero.
	var sawNewContent bool
	deadline = time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		b, readErr := os.ReadFile(outPath)
		if readErr == nil && strings.Contains(string(b), "restarted.local") {
			sawNewContent = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	require.True(t, sawNewContent, "artifact should be rewritten with the new host after reconnect")

	var failuresCleared bool
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if n, ok := readSidecarConsecutiveFailures(t, statusPath); ok && n == 0 {
			failuresCleared = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	require.True(t, failuresCleared, "consecutive failure count should return to zero after reconnect")

	// 6. Cancel the context and assert the command returns.
	runCancel()
	select {
	case runErr := <-runErrCh:
		assert.NoError(t, runErr)
	case <-time.After(10 * time.Second):
		t.Fatal("watch command did not return after context cancellation")
	}
}
