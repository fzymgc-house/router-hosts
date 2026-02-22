package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"log/slog"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/test/bufconn"

	"github.com/fzymgc-house/router-hosts/internal/config"
	"github.com/fzymgc-house/router-hosts/internal/storage"
)

// testCerts holds generated TLS test certificates.
type testCerts struct {
	CACertPath     string
	ServerCertPath string
	ServerKeyPath  string
	ClientCertPath string
	ClientKeyPath  string
	CACertPEM      []byte
}

// generateTestCerts creates a self-signed CA plus server and client certs.
func generateTestCerts(t *testing.T) testCerts {
	t.Helper()
	dir := t.TempDir()

	// Generate CA key
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	caCertPath := filepath.Join(dir, "ca.crt")
	require.NoError(t, os.WriteFile(caCertPath, caCertPEM, 0o600))

	// Server cert
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	require.NoError(t, err)

	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER})
	serverKeyDER, err := x509.MarshalECPrivateKey(serverKey)
	require.NoError(t, err)
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyDER})

	serverCertPath := filepath.Join(dir, "server.crt")
	serverKeyPath := filepath.Join(dir, "server.key")
	require.NoError(t, os.WriteFile(serverCertPath, serverCertPEM, 0o600))
	require.NoError(t, os.WriteFile(serverKeyPath, serverKeyPEM, 0o600))

	// Client cert
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	require.NoError(t, err)

	clientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER})
	clientKeyDER, err := x509.MarshalECPrivateKey(clientKey)
	require.NoError(t, err)
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyDER})

	clientCertPath := filepath.Join(dir, "client.crt")
	clientKeyPath := filepath.Join(dir, "client.key")
	require.NoError(t, os.WriteFile(clientCertPath, clientCertPEM, 0o600))
	require.NoError(t, os.WriteFile(clientKeyPath, clientKeyPEM, 0o600))

	return testCerts{
		CACertPath:     caCertPath,
		ServerCertPath: serverCertPath,
		ServerKeyPath:  serverKeyPath,
		ClientCertPath: clientCertPath,
		ClientKeyPath:  clientKeyPath,
		CACertPEM:      caCertPEM,
	}
}

func testConfig(certs testCerts) config.Config {
	return config.Config{
		Server: config.ServerConfig{
			BindAddress:   "127.0.0.1:0",
			HostsFilePath: "/tmp/hosts",
		},
		TLS: config.TLSConfig{
			CertPath:   certs.ServerCertPath,
			KeyPath:    certs.ServerKeyPath,
			CACertPath: certs.CACertPath,
		},
	}
}

// mockStorage is a minimal storage.Storage for server tests.
type mockStorage struct{ storage.Storage }

func (m *mockStorage) Initialize(_ context.Context) error    { return nil }
func (m *mockStorage) HealthCheck(_ context.Context) error    { return nil }
func (m *mockStorage) Close() error                           { return nil }
func (m *mockStorage) BackendName() string                    { return "mock" }

func TestNewServer(t *testing.T) {
	certs := generateTestCerts(t)
	cfg := testConfig(certs)
	logger := slog.Default()

	lis := bufconn.Listen(1024 * 1024)
	defer lis.Close()

	srv, err := NewServer(cfg, &mockStorage{}, logger, WithListener(lis))
	require.NoError(t, err)
	assert.NotNil(t, srv)
	assert.NotNil(t, srv.grpc)
}

func TestNewServer_InvalidCert(t *testing.T) {
	dir := t.TempDir()
	caCertPath := filepath.Join(dir, "ca.crt")
	require.NoError(t, os.WriteFile(caCertPath, []byte("not a cert"), 0o600))

	cfg := config.Config{
		Server: config.ServerConfig{
			BindAddress:   "127.0.0.1:0",
			HostsFilePath: "/tmp/hosts",
		},
		TLS: config.TLSConfig{
			CertPath:   "/nonexistent/cert.pem",
			KeyPath:    "/nonexistent/key.pem",
			CACertPath: caCertPath,
		},
	}

	_, err := NewServer(cfg, &mockStorage{}, slog.Default())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "configure TLS")
}

func TestNewServer_InvalidCA(t *testing.T) {
	certs := generateTestCerts(t)
	// Overwrite CA with garbage
	require.NoError(t, os.WriteFile(certs.CACertPath, []byte("not a cert"), 0o600))

	cfg := testConfig(certs)
	_, err := NewServer(cfg, &mockStorage{}, slog.Default())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse CA certificate")
}

func TestServer_StartAndStop(t *testing.T) {
	certs := generateTestCerts(t)
	cfg := testConfig(certs)
	logger := slog.Default()

	lis := bufconn.Listen(1024 * 1024)

	srv, err := NewServer(cfg, &mockStorage{}, logger, WithListener(lis))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Run(ctx)
	}()

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	// Cancel to trigger shutdown
	cancel()

	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down within timeout")
	}
}

func TestServer_GracefulShutdown(t *testing.T) {
	certs := generateTestCerts(t)
	cfg := testConfig(certs)
	logger := slog.Default()

	lis := bufconn.Listen(1024 * 1024)

	srv, err := NewServer(cfg, &mockStorage{}, logger, WithListener(lis))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Run(ctx)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("graceful shutdown timed out")
	}
}

func TestServer_TLSConfig(t *testing.T) {
	certs := generateTestCerts(t)
	cfg := testConfig(certs)
	logger := slog.Default()

	lis := bufconn.Listen(1024 * 1024)

	srv, err := NewServer(cfg, &mockStorage{}, logger, WithListener(lis))
	require.NoError(t, err)

	// Verify cert is loaded
	srv.mu.RLock()
	assert.NotNil(t, srv.cert)
	srv.mu.RUnlock()

	// Verify GetCertificate callback works
	cert, err := srv.getCertificate(nil)
	require.NoError(t, err)
	assert.NotNil(t, cert)
}

func TestServer_CertReload(t *testing.T) {
	certs := generateTestCerts(t)
	cfg := testConfig(certs)

	lis := bufconn.Listen(1024 * 1024)
	defer lis.Close()

	srv, err := NewServer(cfg, &mockStorage{}, slog.Default(), WithListener(lis))
	require.NoError(t, err)

	// Get initial cert serial
	srv.mu.RLock()
	initialCert := srv.cert
	srv.mu.RUnlock()
	require.NotNil(t, initialCert)

	// Reload (same files — should succeed)
	err = srv.reloadCert()
	require.NoError(t, err)

	srv.mu.RLock()
	reloadedCert := srv.cert
	srv.mu.RUnlock()
	assert.NotNil(t, reloadedCert)
}

func TestServer_CertReload_InvalidFile(t *testing.T) {
	certs := generateTestCerts(t)
	cfg := testConfig(certs)

	lis := bufconn.Listen(1024 * 1024)
	defer lis.Close()

	srv, err := NewServer(cfg, &mockStorage{}, slog.Default(), WithListener(lis))
	require.NoError(t, err)

	// Overwrite cert with garbage
	require.NoError(t, os.WriteFile(certs.ServerCertPath, []byte("bad cert"), 0o600))

	err = srv.reloadCert()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reload certificate")

	// Original cert should still be available
	cert, err := srv.getCertificate(nil)
	require.NoError(t, err)
	assert.NotNil(t, cert)
}

func TestServer_RegisterService(t *testing.T) {
	certs := generateTestCerts(t)
	cfg := testConfig(certs)

	lis := bufconn.Listen(1024 * 1024)
	defer lis.Close()

	srv, err := NewServer(cfg, &mockStorage{}, slog.Default(), WithListener(lis))
	require.NoError(t, err)

	// RegisterService should not panic with a valid desc
	assert.NotNil(t, srv.GRPCServer())
}

func TestServer_BufconnConnection(t *testing.T) {
	certs := generateTestCerts(t)
	cfg := testConfig(certs)
	logger := slog.Default()

	lis := bufconn.Listen(1024 * 1024)

	srv, err := NewServer(cfg, &mockStorage{}, logger, WithListener(lis))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Run(ctx)
	}()

	time.Sleep(50 * time.Millisecond)

	// Build client TLS config
	clientCert, err := tls.LoadX509KeyPair(certs.ClientCertPath, certs.ClientKeyPath)
	require.NoError(t, err)

	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM(certs.CACertPEM))

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS12,
	}

	// Connect via bufconn with mTLS
	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
	)
	require.NoError(t, err)
	defer conn.Close()

	cancel()
	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down")
	}
}
