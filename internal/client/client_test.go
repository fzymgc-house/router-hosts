package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fzymgc-house/router-hosts/internal/config"
	"github.com/fzymgc-house/router-hosts/internal/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient_NoTLS_ReturnsError(t *testing.T) {
	cfg := &config.ClientConfig{
		Server: config.ClientServerConfig{Address: "localhost:50051"},
	}

	_, err := NewClient(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TLS configuration required")
}

func TestNewClient_Close_Nil(t *testing.T) {
	c := &Client{}
	assert.NoError(t, c.Close())
}

func TestBuildTransportCredentials_NoTLS_ReturnsError(t *testing.T) {
	cfg := &config.ClientConfig{Server: config.ClientServerConfig{Address: "localhost:50051"}}
	_, err := buildTransportCredentials(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TLS configuration required")
}

func TestBuildTransportCredentials_MismatchedCertKey(t *testing.T) {
	cfg := &config.ClientConfig{
		Server: config.ClientServerConfig{Address: "localhost:50051"},
		TLS:    config.ClientTLSConfig{CertPath: "/some/cert.pem"},
	}
	_, err := buildTransportCredentials(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cert_path and key_path must both be set or both be empty")
}

func TestBuildTransportCredentials_MismatchedKeyWithoutCert(t *testing.T) {
	cfg := &config.ClientConfig{
		Server: config.ClientServerConfig{Address: "localhost:50051"},
		TLS:    config.ClientTLSConfig{KeyPath: "/some/key.pem"},
	}
	_, err := buildTransportCredentials(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cert_path and key_path must both be set or both be empty")
}

func TestBuildTransportCredentials_WithTLS(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, caFile := generateTestCerts(t, dir)

	cfg := &config.ClientConfig{
		Server: config.ClientServerConfig{Address: "localhost:50051"},
		TLS: config.ClientTLSConfig{
			CertPath:   certFile,
			KeyPath:    keyFile,
			CACertPath: caFile,
		},
	}

	creds, err := buildTransportCredentials(cfg)
	require.NoError(t, err)
	assert.NotNil(t, creds)

	// Should not be insecure
	info := creds.Info()
	assert.Equal(t, "tls", info.SecurityProtocol)
}

func TestBuildTransportCredentials_CAOnly(t *testing.T) {
	dir := t.TempDir()
	_, _, caFile := generateTestCerts(t, dir)

	cfg := &config.ClientConfig{
		Server: config.ClientServerConfig{Address: "localhost:50051"},
		TLS:    config.ClientTLSConfig{CACertPath: caFile},
	}

	creds, err := buildTransportCredentials(cfg)
	require.NoError(t, err)
	assert.NotNil(t, creds)

	// Should be valid TLS without client certificate
	info := creds.Info()
	assert.Equal(t, "tls", info.SecurityProtocol)
}

func TestBuildTransportCredentials_BadCertPath(t *testing.T) {
	cfg := &config.ClientConfig{
		Server: config.ClientServerConfig{Address: "localhost:50051"},
		TLS: config.ClientTLSConfig{
			CertPath: "/nonexistent/cert.pem",
			KeyPath:  "/nonexistent/key.pem",
		},
	}

	_, err := buildTransportCredentials(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "loading client certificate")
}

func TestBuildTransportCredentials_BadCAPath(t *testing.T) {
	cfg := &config.ClientConfig{
		Server: config.ClientServerConfig{Address: "localhost:50051"},
		TLS:    config.ClientTLSConfig{CACertPath: "/nonexistent/ca.pem"},
	}

	_, err := buildTransportCredentials(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "reading CA certificate")
}

func TestBuildTransportCredentials_InvalidCAPEM(t *testing.T) {
	dir := t.TempDir()
	caFile := filepath.Join(dir, "bad-ca.pem")
	require.NoError(t, os.WriteFile(caFile, []byte("not a PEM"), 0o600))

	cfg := &config.ClientConfig{
		Server: config.ClientServerConfig{Address: "localhost:50051"},
		TLS:    config.ClientTLSConfig{CACertPath: caFile},
	}

	_, err := buildTransportCredentials(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse CA certificate")
}

// generateTestCerts creates a self-signed CA + client cert for testing.
func generateTestCerts(t *testing.T, dir string) (certPath, keyPath, caPath string) {
	t.Helper()

	// Generate CA key
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caPath = filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600))

	// Generate client key + cert signed by CA
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Client"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, &clientKey.PublicKey, caKey)
	require.NoError(t, err)

	certPath = filepath.Join(dir, "client.pem")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}), 0o600))

	keyDER, err := x509.MarshalECPrivateKey(clientKey)
	require.NoError(t, err)

	keyPath = filepath.Join(dir, "client-key.pem")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))

	return certPath, keyPath, caPath
}

// ---------------------------------------------------------------------------
// gRPC keepalive (TMPL-06 amended plan, review L14/D-09/T-1-13)
// ---------------------------------------------------------------------------

func TestKeepalive_ClientParams(t *testing.T) {
	params := KeepaliveParams()
	assert.Equal(t, 20*time.Second, params.Time, "client ping interval")
	assert.Equal(t, 10*time.Second, params.Timeout, "client ping timeout")
	assert.True(t, params.PermitWithoutStream, "pings must continue with no active RPC")
}

// TestKeepalive_ClientIntervalRespectsServerMinTime pins the invariant that
// silently produces GOAWAY storms when violated: a client pinging more often
// than the server's enforcement minimum gets disconnected.
func TestKeepalive_ClientIntervalRespectsServerMinTime(t *testing.T) {
	clientTime := KeepaliveParams().Time
	serverMinTime := server.KeepaliveEnforcementPolicy().MinTime
	assert.GreaterOrEqual(t, clientTime, serverMinTime)
}

// ---------------------------------------------------------------------------
// Stream collection limits (D-14, TMPL-07, review L1/L6).
// ---------------------------------------------------------------------------

func TestClient_MaxStreamEntriesFromConfig(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, caFile := generateTestCerts(t, dir)
	cfg := &config.ClientConfig{
		Server: config.ClientServerConfig{Address: "localhost:50051"},
		TLS:    config.ClientTLSConfig{CertPath: certFile, KeyPath: keyFile, CACertPath: caFile},
		Limits: config.ClientLimitsConfig{MaxStreamEntries: 42},
	}

	c, err := NewClient(cfg)
	require.NoError(t, err)
	assert.Equal(t, 42, c.MaxStreamEntries())
}

func TestClient_MaxStreamEntriesDefaultsFromConn(t *testing.T) {
	c := NewClientFromConn(nil)
	assert.Equal(t, config.DefaultMaxStreamEntries, c.MaxStreamEntries())
	assert.Equal(t, int64(config.DefaultMaxStreamBytes), c.MaxStreamBytes())
}

func TestClient_MaxStreamBytesFromConfig(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, caFile := generateTestCerts(t, dir)
	cfg := &config.ClientConfig{
		Server: config.ClientServerConfig{Address: "localhost:50051"},
		TLS:    config.ClientTLSConfig{CertPath: certFile, KeyPath: keyFile, CACertPath: caFile},
		Limits: config.ClientLimitsConfig{MaxStreamBytes: 8192},
	}

	c, err := NewClient(cfg)
	require.NoError(t, err)
	assert.Equal(t, int64(8192), c.MaxStreamBytes())
}

func TestClient_OptionOverridesConfiguredLimit(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, caFile := generateTestCerts(t, dir)
	cfg := &config.ClientConfig{
		Server: config.ClientServerConfig{Address: "localhost:50051"},
		TLS:    config.ClientTLSConfig{CertPath: certFile, KeyPath: keyFile, CACertPath: caFile},
		Limits: config.ClientLimitsConfig{MaxStreamEntries: 42, MaxStreamBytes: 8192},
	}

	c, err := NewClient(cfg, WithMaxStreamEntries(3), WithMaxStreamBytes(100))
	require.NoError(t, err)
	assert.Equal(t, 3, c.MaxStreamEntries())
	assert.Equal(t, int64(100), c.MaxStreamBytes())
}
