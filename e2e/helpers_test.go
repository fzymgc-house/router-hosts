//go:build e2e

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

	// Create a listener on a random port so we know the address
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "listen on random port")
	addr := lis.Addr().String()

	// Create server
	handler := server.NewCommandHandler(store)
	svc := server.NewHostsServiceImpl(handler, store)

	srv, err := server.NewServer(cfg, store, logger, server.WithListener(lis))
	require.NoError(t, err, "create server")

	hostsv1.RegisterHostsServiceServer(srv.GRPCServer(), svc)

	// Start server in background
	ctx, cancel := context.WithCancel(context.Background())
	srvErrCh := make(chan error, 1)
	go func() {
		srvErrCh <- srv.Run(ctx)
	}()

	// Wait for server to be ready
	waitForServer(t, addr, caCertPath, clientCertPath, clientKeyPath)

	// Create client connection
	conn := dialGRPC(t, addr, caCertPath, clientCertPath, clientKeyPath)
	client := hostsv1.NewHostsServiceClient(conn)

	env := &testEnv{
		client:         client,
		conn:           conn,
		srv:            srv,
		cancel:         cancel,
		tmpDir:         tmpDir,
		caCertPath:     caCertPath,
		serverCertPath: serverCertPath,
		serverKeyPath:  serverKeyPath,
		clientCertPath: clientCertPath,
		clientKeyPath:  clientKeyPath,
	}

	t.Cleanup(func() {
		cancel()
		// Wait for server to fully shut down before closing resources
		select {
		case <-srvErrCh:
		case <-time.After(5 * time.Second):
			t.Log("server shutdown timed out")
		}
		conn.Close()
		store.Close()
	})

	return env
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
		MinVersion:   tls.VersionTLS12,
	}
}

// waitForServer polls the server until it accepts a TLS connection.
func waitForServer(t *testing.T, addr, caCertPath, clientCertPath, clientKeyPath string) {
	t.Helper()

	tlsCfg := buildClientTLSConfig(t, caCertPath, clientCertPath, clientKeyPath)

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 500 * time.Millisecond},
			"tcp", addr, tlsCfg,
		)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("server at %s did not become ready within 10 seconds", addr)
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
		if err == io.EOF {
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
		if err == io.EOF {
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
		if err == io.EOF {
			break
		}
		require.NoError(t, err, "recv ListSnapshots")
		snapshots = append(snapshots, resp.GetSnapshot())
	}
	return snapshots
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
		MinVersion:   tls.VersionTLS12,
	}

	conn, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
	)
	require.NoError(t, err)
	return conn
}
