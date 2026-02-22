package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fzymgc-house/router-hosts/internal/config"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func testACMEConfig(t *testing.T) config.ACMEConfig {
	t.Helper()
	return config.ACMEConfig{
		Enabled:       true,
		DirectoryURL:  "https://acme-staging-v02.api.letsencrypt.org/directory",
		Email:         "test@example.com",
		Domains:       []string{"example.com"},
		DNS:           config.ACMEDNSConfig{Provider: "cloudflare", Cloudflare: &config.CloudflareDNS{APIToken: "test-token"}},
		RenewalDays:   30,
		CheckInterval: 1, // 1 second for tests
		StoragePath:   t.TempDir(),
	}
}

func testTLSConfig(t *testing.T) config.TLSConfig {
	t.Helper()
	dir := t.TempDir()
	return config.TLSConfig{
		CertPath:   filepath.Join(dir, "cert.pem"),
		KeyPath:    filepath.Join(dir, "key.pem"),
		CACertPath: filepath.Join(dir, "ca.pem"),
	}
}

// generateTestCert creates a self-signed certificate with the given NotAfter time.
func generateTestCert(t *testing.T, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
}

// mockObtain returns a mock obtain function that writes a test cert expiring at notAfter.
func mockObtain(t *testing.T, notAfter time.Time) obtainFunc {
	t.Helper()
	return func(_ context.Context, domains []string) (*certificate.Resource, error) {
		certPEM, keyPEM := generateTestCert(t, notAfter)
		return &certificate.Resource{
			Domain:      domains[0],
			Certificate: certPEM,
			PrivateKey:  keyPEM,
		}, nil
	}
}

func TestNewManager_Defaults(t *testing.T) {
	acmeCfg := testACMEConfig(t)
	tlsCfg := testTLSConfig(t)

	m, err := NewManager(acmeCfg, tlsCfg, testLogger(), nil,
		WithObtainFunc(mockObtain(t, time.Now().Add(90*24*time.Hour))))
	require.NoError(t, err)

	assert.Equal(t, acmeCfg.Email, m.cfg.Email)
	assert.Equal(t, acmeCfg.DirectoryURL, m.cfg.DirectoryURL)
	assert.Equal(t, acmeCfg.RenewalDays, m.cfg.RenewalDays)
	assert.Equal(t, acmeCfg.CheckInterval, m.cfg.CheckInterval)
	assert.NotNil(t, m.obtain)
}

func TestRenewIfNeeded_NotExpiring(t *testing.T) {
	acmeCfg := testACMEConfig(t)
	tlsCfg := testTLSConfig(t)

	// Write a cert that expires far in the future (90 days)
	notAfter := time.Now().Add(90 * 24 * time.Hour)
	certPEM, keyPEM := generateTestCert(t, notAfter)
	require.NoError(t, os.WriteFile(tlsCfg.CertPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(tlsCfg.KeyPath, keyPEM, 0o600))

	renewCalled := false
	m, err := NewManager(acmeCfg, tlsCfg, testLogger(), func() error {
		renewCalled = true
		return nil
	}, WithObtainFunc(mockObtain(t, notAfter)))
	require.NoError(t, err)

	renewed, err := m.RenewIfNeeded(context.Background())
	require.NoError(t, err)
	assert.False(t, renewed, "should not renew a cert with 90 days left")
	assert.False(t, renewCalled)
}

func TestRenewIfNeeded_WithinWindow(t *testing.T) {
	acmeCfg := testACMEConfig(t)
	tlsCfg := testTLSConfig(t)

	// Write a cert that expires in 5 days (within 30-day renewal window)
	oldNotAfter := time.Now().Add(5 * 24 * time.Hour)
	certPEM, keyPEM := generateTestCert(t, oldNotAfter)
	require.NoError(t, os.WriteFile(tlsCfg.CertPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(tlsCfg.KeyPath, keyPEM, 0o600))

	renewCalled := false
	newNotAfter := time.Now().Add(90 * 24 * time.Hour)
	m, err := NewManager(acmeCfg, tlsCfg, testLogger(), func() error {
		renewCalled = true
		return nil
	}, WithObtainFunc(mockObtain(t, newNotAfter)))
	require.NoError(t, err)

	renewed, err := m.RenewIfNeeded(context.Background())
	require.NoError(t, err)
	assert.True(t, renewed, "should renew a cert expiring in 5 days")
	assert.True(t, renewCalled)

	// Verify new cert was written
	newCertPEM, err := os.ReadFile(tlsCfg.CertPath)
	require.NoError(t, err)
	block, _ := pem.Decode(newCertPEM)
	require.NotNil(t, block)
	newCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.True(t, newCert.NotAfter.After(oldNotAfter), "new cert should expire later than old cert")
}

func TestRenewIfNeeded_NoCertOnDisk(t *testing.T) {
	acmeCfg := testACMEConfig(t)
	tlsCfg := testTLSConfig(t)

	m, err := NewManager(acmeCfg, tlsCfg, testLogger(), nil,
		WithObtainFunc(mockObtain(t, time.Now().Add(90*24*time.Hour))))
	require.NoError(t, err)

	_, err = m.RenewIfNeeded(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading certificate")
}

func TestObtainCertificate(t *testing.T) {
	acmeCfg := testACMEConfig(t)
	tlsCfg := testTLSConfig(t)

	notAfter := time.Now().Add(90 * 24 * time.Hour)
	m, err := NewManager(acmeCfg, tlsCfg, testLogger(), nil,
		WithObtainFunc(mockObtain(t, notAfter)))
	require.NoError(t, err)

	err = m.ObtainCertificate(context.Background())
	require.NoError(t, err)

	// Verify cert and key were written
	certData, err := os.ReadFile(tlsCfg.CertPath)
	require.NoError(t, err)
	assert.NotEmpty(t, certData)

	keyData, err := os.ReadFile(tlsCfg.KeyPath)
	require.NoError(t, err)
	assert.NotEmpty(t, keyData)

	// Verify cert permissions
	info, err := os.Stat(tlsCfg.CertPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	info, err = os.Stat(tlsCfg.KeyPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestStartStop(t *testing.T) {
	acmeCfg := testACMEConfig(t)
	acmeCfg.CheckInterval = 1 // 1-second interval for fast test
	tlsCfg := testTLSConfig(t)

	// Write a cert far from expiry so no actual renewal happens
	notAfter := time.Now().Add(90 * 24 * time.Hour)
	certPEM, keyPEM := generateTestCert(t, notAfter)
	require.NoError(t, os.WriteFile(tlsCfg.CertPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(tlsCfg.KeyPath, keyPEM, 0o600))

	m, err := NewManager(acmeCfg, tlsCfg, testLogger(), nil,
		WithObtainFunc(mockObtain(t, notAfter)))
	require.NoError(t, err)

	ctx := context.Background()
	m.Start(ctx)

	// Wait enough for at least one tick
	time.Sleep(1500 * time.Millisecond)

	// Stop should complete without hanging
	done := make(chan struct{})
	go func() {
		m.Stop()
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(5 * time.Second):
		t.Fatal("Stop() did not return within timeout")
	}
}

func TestStartStop_ContextCancel(t *testing.T) {
	acmeCfg := testACMEConfig(t)
	acmeCfg.CheckInterval = 60 // won't tick during test
	tlsCfg := testTLSConfig(t)

	notAfter := time.Now().Add(90 * 24 * time.Hour)
	certPEM, keyPEM := generateTestCert(t, notAfter)
	require.NoError(t, os.WriteFile(tlsCfg.CertPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(tlsCfg.KeyPath, keyPEM, 0o600))

	m, err := NewManager(acmeCfg, tlsCfg, testLogger(), nil,
		WithObtainFunc(mockObtain(t, notAfter)))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	m.Start(ctx)

	// Cancel context should cause renewal loop to exit
	cancel()

	select {
	case <-m.stopped:
		// OK
	case <-time.After(5 * time.Second):
		t.Fatal("renewal loop did not stop on context cancel")
	}
}

func TestStop_Idempotent(t *testing.T) {
	acmeCfg := testACMEConfig(t)
	acmeCfg.CheckInterval = 60
	tlsCfg := testTLSConfig(t)

	notAfter := time.Now().Add(90 * 24 * time.Hour)
	certPEM, keyPEM := generateTestCert(t, notAfter)
	require.NoError(t, os.WriteFile(tlsCfg.CertPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(tlsCfg.KeyPath, keyPEM, 0o600))

	m, err := NewManager(acmeCfg, tlsCfg, testLogger(), nil,
		WithObtainFunc(mockObtain(t, notAfter)))
	require.NoError(t, err)

	m.Start(context.Background())
	m.Stop()
	// Second stop should not panic or block
	m.Stop()
}

func TestStop_WithoutStart(t *testing.T) {
	acmeCfg := testACMEConfig(t)
	tlsCfg := testTLSConfig(t)

	m, err := NewManager(acmeCfg, tlsCfg, testLogger(), nil,
		WithObtainFunc(mockObtain(t, time.Now().Add(90*24*time.Hour))))
	require.NoError(t, err)

	// Stop without Start should not deadlock or panic.
	done := make(chan struct{})
	go func() {
		m.Stop()
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() without Start() deadlocked")
	}
}

func TestStart_Idempotent(t *testing.T) {
	acmeCfg := testACMEConfig(t)
	acmeCfg.CheckInterval = 60
	tlsCfg := testTLSConfig(t)

	notAfter := time.Now().Add(90 * 24 * time.Hour)
	certPEM, keyPEM := generateTestCert(t, notAfter)
	require.NoError(t, os.WriteFile(tlsCfg.CertPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(tlsCfg.KeyPath, keyPEM, 0o600))

	m, err := NewManager(acmeCfg, tlsCfg, testLogger(), nil,
		WithObtainFunc(mockObtain(t, notAfter)))
	require.NoError(t, err)

	ctx := context.Background()
	// Multiple Start calls should not panic or spawn extra goroutines.
	m.Start(ctx)
	m.Start(ctx)
	m.Start(ctx)
	m.Stop()
}

func TestAccountFilePath(t *testing.T) {
	acmeCfg := testACMEConfig(t)
	tlsCfg := testTLSConfig(t)

	m, err := NewManager(acmeCfg, tlsCfg, testLogger(), nil,
		WithObtainFunc(mockObtain(t, time.Now().Add(90*24*time.Hour))))
	require.NoError(t, err)

	expected := filepath.Join(acmeCfg.StoragePath, "account.json")
	assert.Equal(t, expected, m.accountFilePath())
}
