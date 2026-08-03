//go:build e2e || docker_e2e

package e2e_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
	"github.com/fzymgc-house/router-hosts/internal/config"
	"github.com/fzymgc-house/router-hosts/internal/server"
	"github.com/fzymgc-house/router-hosts/internal/storage/sqlite"
	"github.com/fzymgc-house/router-hosts/internal/testutil/wait"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// testEnv holds a running server, gRPC client, and cleanup resources for E2E tests.
type testEnv struct {
	client hostsv1.HostsServiceClient
	conn   *grpc.ClientConn
	srv    *server.Server
	cancel context.CancelFunc
	tmpDir string

	// Cert paths for auth failure tests
	caCertPath     string
	serverCertPath string
	serverKeyPath  string
	clientCertPath string
	clientKeyPath  string

	// Per-start lifecycle state (review round-2 H6, M10). Replaced on every
	// startServer call; stopServer relies on these rather than any local in
	// setupTestEnv, so a second stop/start cycle cannot hang on a stale
	// cancel or a consumed channel.
	addr       string
	sinkHealth *server.SinkHealth
	srvErrCh   chan error
	running    bool

	// Construction inputs, retained so startServer can actually build a
	// fresh server and service over the SAME store after a stop (review
	// round-3 H5). Lifecycle state alone is not enough: nothing else on this
	// struct lets a second server be constructed at all.
	store  *sqlite.Storage
	cfg    config.Config
	logger *slog.Logger
}

// setupTestEnv creates a full mTLS test environment with a running gRPC server
// backed by an in-memory SQLite database. The server listens on a random port
// on localhost with real TLS.
func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()

	tmpDir := t.TempDir()

	// Generate CA + server cert + client cert
	ca, caCertPEM, caKeyPEM := generateCA(t)
	serverCertPEM, serverKeyPEM := generateCert(t, ca, caKeyPEM, true)
	clientCertPEM, clientKeyPEM := generateCert(t, ca, caKeyPEM, false)

	// Write certs to disk
	caCertPath := writePEM(t, tmpDir, "ca.crt", caCertPEM)
	serverCertPath := writePEM(t, tmpDir, "server.crt", serverCertPEM)
	serverKeyPath := writePEM(t, tmpDir, "server.key", serverKeyPEM)
	clientCertPath := writePEM(t, tmpDir, "client.crt", clientCertPEM)
	clientKeyPath := writePEM(t, tmpDir, "client.key", clientKeyPEM)

	// SQLite database
	dbPath := filepath.Join(tmpDir, "hosts.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	store, err := sqlite.New(dbPath, logger)
	require.NoError(t, err, "create sqlite storage")

	err = store.Initialize(context.Background())
	require.NoError(t, err, "initialize sqlite storage")

	// Config
	hostsFilePath := filepath.Join(tmpDir, "hosts")
	cfg := config.Config{
		Server: config.ServerConfig{
			BindAddress:   "127.0.0.1:0",
			HostsFilePath: hostsFilePath,
		},
		Database: config.DatabaseConfig{
			Path: dbPath,
		},
		TLS: config.TLSConfig{
			CertPath:   serverCertPath,
			KeyPath:    serverKeyPath,
			CACertPath: caCertPath,
		},
	}

	env := &testEnv{
		tmpDir:         tmpDir,
		caCertPath:     caCertPath,
		serverCertPath: serverCertPath,
		serverKeyPath:  serverKeyPath,
		clientCertPath: clientCertPath,
		clientKeyPath:  clientKeyPath,
		sinkHealth:     server.NewSinkHealth(),
		store:          store,
		cfg:            cfg,
		logger:         logger,
	}

	// startServer does the listen-build-run-dial sequence exactly once here
	// (env.addr is empty, so it binds to a fresh random port), and again on
	// every later restart in a test — proving startServer is genuinely the
	// shared path rather than a description of one.
	startServer(t, env)

	t.Cleanup(func() {
		// stopServer is idempotent, so this is correct whether a test left
		// the server running or already stopped it itself.
		stopServer(t, env)
		_ = store.Close()
	})

	return env
}

// stopServer tears down the running server and closes the client
// connection, leaving a real, externally observable outage until
// startServer is called again (reviews M4, M10). Idempotent: a call when
// env.running is already false returns immediately, so t.Cleanup can call it
// unconditionally regardless of what a test already did.
func stopServer(t *testing.T, env *testEnv) {
	t.Helper()

	if !env.running {
		return
	}

	// Stop immediately rather than relying on context cancellation alone:
	// Server.Run's ctx.Done() path calls gracefulStop, which drains for up
	// to GracefulShutdownTimeout (30s) before forcing anything, keeping
	// this test's open WatchHosts stream alive for the whole grace window —
	// exactly the "restart returns already-healthy" failure mode reviews
	// M4/M10 rejected, just delayed rather than absent. A real server
	// process going down does not wait for existing streams to finish
	// either, so Stop() (grpc.Server.Stop, immediate) is the accurate
	// simulation; env.cancel() still runs so Run's own goroutine unwinds
	// promptly once its Serve call returns.
	env.srv.Stop()
	env.cancel()
	select {
	case <-env.srvErrCh:
	case <-time.After(5 * time.Second):
		t.Log("server shutdown timed out")
	}

	// Close and nil the client connection here (review round-3 M6): a
	// helper call made against a stopped server must fail loudly rather
	// than block in gRPC's transparent-reconnect backoff.
	if env.conn != nil {
		_ = env.conn.Close()
		env.conn = nil
		env.client = nil
	}

	env.running = false
}

// startServer (re)binds env.addr (choosing a fresh random port only the
// first time it is empty; every later call rebinds the SAME address so a
// restart is a genuine redial target), builds a fresh server and service
// over the RETAINED store, config, logger and sink-health registry (review
// round-3 H5) — never a new store, which would defeat the whole point of a
// restart test — registers the service, starts it, waits for readiness,
// and finally redials the client connection (review round-3 M6). The harness
// redials on every start as its own stated contract; the real
// `router-hosts watch` process under test is deliberately NOT touched here
// and is left to reconnect using its own transparent-retry policy, which is
// exactly what TestE2E_WatchSinkSurvivesServerRestart exists to verify.
func startServer(t *testing.T, env *testEnv) {
	t.Helper()

	bindAddr := env.addr
	if bindAddr == "" {
		bindAddr = "127.0.0.1:0"
	}

	// Rebinding an address whose previous connections may still be in
	// TIME_WAIT can transiently fail on some platforms (review L4), so this
	// retries a bounded number of times rather than asserting on the first
	// attempt.
	const maxBindAttempts = 20
	const bindRetryDelay = 100 * time.Millisecond
	var lis net.Listener
	wait.Until(t, maxBindAttempts*bindRetryDelay, bindRetryDelay,
		fmt.Sprintf("listener to bind on %s", bindAddr),
		func() bool {
			l, err := net.Listen("tcp", bindAddr)
			if err != nil {
				return false
			}
			lis = l
			return true
		},
	)
	env.addr = lis.Addr().String()

	handler := server.NewCommandHandler(env.store)
	svc := server.NewHostsServiceImpl(handler, env.store, server.WithSinkHealth(env.sinkHealth))

	srv, err := server.NewServer(env.cfg, env.store, env.logger, server.WithListener(lis))
	require.NoError(t, err, "create server")

	hostsv1.RegisterHostsServiceServer(srv.GRPCServer(), svc)

	ctx, cancel := context.WithCancel(context.Background())
	srvErrCh := make(chan error, 1)
	go func() {
		srvErrCh <- srv.Run(ctx)
	}()

	waitForServer(t, env.addr, env.caCertPath, env.clientCertPath, env.clientKeyPath)

	env.srv = srv
	env.cancel = cancel
	env.srvErrCh = srvErrCh

	// Redial per start (review round-3 M6): closes over no prior conn since
	// stopServer already nil'd it (or this is the first start).
	env.conn = dialGRPC(t, env.addr, env.caCertPath, env.clientCertPath, env.clientKeyPath)
	env.client = hostsv1.NewHostsServiceClient(env.conn)

	env.running = true
}

// generateCA creates a self-signed CA certificate and private key.
func generateCA(t *testing.T) (*x509.Certificate, []byte, []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"router-hosts E2E Test CA"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return cert, certPEM, keyPEM
}

// generateCert creates a certificate signed by the given CA.
// If isServer is true, SANs include localhost and 127.0.0.1 with server auth usage.
// Otherwise, it creates a client auth certificate.
func generateCert(t *testing.T, ca *x509.Certificate, caKeyPEM []byte, isServer bool) (certPEM, keyPEM []byte) {
	t.Helper()

	caKeyBlock, _ := pem.Decode(caKeyPEM)
	require.NotNil(t, caKeyBlock)
	caKey, err := x509.ParseECPrivateKey(caKeyBlock.Bytes)
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"router-hosts E2E Test"},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	if isServer {
		template.Subject.CommonName = "localhost"
		template.DNSNames = []string{"localhost"}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	} else {
		template.Subject.CommonName = "e2e-test-client"
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
}

// writePEM writes PEM data to a file in the given directory and returns the path.
func writePEM(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	err := os.WriteFile(path, data, 0o600)
	require.NoError(t, err, "write %s", name)
	return path
}

// buildClientTLSConfig creates a TLS config for client connections from cert files on disk.
func buildClientTLSConfig(t *testing.T, caCertPath, clientCertPath, clientKeyPath string) *tls.Config {
	t.Helper()

	caCert, err := os.ReadFile(caCertPath)
	require.NoError(t, err)
	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM(caCert))

	clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	require.NoError(t, err)

	return &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		// TLS 1.3, matching what production client credentials enforce
		// (internal/client/client.go), so a direct harness dial exercises
		// the same policy any real client uses rather than a weaker one
		// (review L10).
		MinVersion: tls.VersionTLS13,
	}
}

// waitForServer polls the server until it accepts a TLS connection.
func waitForServer(t *testing.T, addr, caCertPath, clientCertPath, clientKeyPath string) {
	t.Helper()

	tlsCfg := buildClientTLSConfig(t, caCertPath, clientCertPath, clientKeyPath)

	wait.Until(t, 10*time.Second, 50*time.Millisecond, fmt.Sprintf("server at %s to accept a TLS connection", addr), func() bool {
		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 500 * time.Millisecond},
			"tcp", addr, tlsCfg,
		)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	})
}

// dialGRPC creates a gRPC client connection with mTLS.
func dialGRPC(t *testing.T, addr, caCertPath, clientCertPath, clientKeyPath string) *grpc.ClientConn {
	t.Helper()

	tlsCfg := buildClientTLSConfig(t, caCertPath, clientCertPath, clientKeyPath)

	conn, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
	)
	require.NoError(t, err)
	return conn
}

// collectListHosts drains a ListHosts server stream and returns all entries.
func collectListHosts(t *testing.T, stream grpc.ServerStreamingClient[hostsv1.ListHostsResponse]) []*hostsv1.HostEntry {
	t.Helper()
	var entries []*hostsv1.HostEntry
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err, "recv ListHosts")
		entries = append(entries, resp.GetEntry())
	}
	return entries
}

// collectSearchHosts drains a SearchHosts server stream and returns all entries.
func collectSearchHosts(t *testing.T, stream grpc.ServerStreamingClient[hostsv1.SearchHostsResponse]) []*hostsv1.HostEntry {
	t.Helper()
	var entries []*hostsv1.HostEntry
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err, "recv SearchHosts")
		entries = append(entries, resp.GetEntry())
	}
	return entries
}

// collectListSnapshots drains a ListSnapshots server stream and returns all snapshots.
func collectListSnapshots(t *testing.T, stream grpc.ServerStreamingClient[hostsv1.ListSnapshotsResponse]) []*hostsv1.Snapshot {
	t.Helper()
	var snapshots []*hostsv1.Snapshot
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err, "recv ListSnapshots")
		snapshots = append(snapshots, resp.GetSnapshot())
	}
	return snapshots
}

// collectWatchSnapshot drains a WatchHosts client stream, mirroring
// collectListHosts's shape, and returns as soon as a SnapshotComplete
// terminator arrives (or the stream ends first, in which case the
// terminator return is nil). Calling it again on the same still-open
// follow-mode stream collects the NEXT snapshot's entries and terminator,
// which is how the follow-mode tests observe a push after a mutation.
func collectWatchSnapshot(t *testing.T, stream grpc.BidiStreamingClient[hostsv1.WatchHostsRequest, hostsv1.WatchHostsResponse]) ([]*hostsv1.HostEntry, *hostsv1.SnapshotComplete) {
	t.Helper()
	var entries []*hostsv1.HostEntry
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return entries, nil
		}
		require.NoError(t, err, "recv WatchHosts")
		if e := resp.GetEntry(); e != nil {
			entries = append(entries, e)
			continue
		}
		if comp := resp.GetComplete(); comp != nil {
			return entries, comp
		}
	}
}

// ptr returns a pointer to v.
func ptr[T any](v T) *T {
	return &v
}

// serverAddr extracts the address from a testEnv by reading the underlying connection target.
func serverAddr(t *testing.T, env *testEnv) string {
	t.Helper()
	return env.conn.Target()
}

// dialGRPCWithCerts creates a gRPC connection using raw PEM bytes.
func dialGRPCWithCerts(t *testing.T, addr string, caCertPEM, clientCertPEM, clientKeyPEM []byte) *grpc.ClientConn {
	t.Helper()

	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM(caCertPEM), "parse CA cert PEM")

	clientCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	require.NoError(t, err, "load client key pair")

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	}

	conn, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
	)
	require.NoError(t, err)
	return conn
}
