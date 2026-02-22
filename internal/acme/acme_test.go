package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/registration"
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

// --- acmeAccount getter tests ---

func TestAcmeAccount_GetEmail(t *testing.T) {
	a := &acmeAccount{Email: "user@example.com"}
	assert.Equal(t, "user@example.com", a.GetEmail())
}

func TestAcmeAccount_GetEmail_Empty(t *testing.T) {
	a := &acmeAccount{}
	assert.Equal(t, "", a.GetEmail())
}

func TestAcmeAccount_GetRegistration(t *testing.T) {
	reg := &registration.Resource{URI: "https://acme.example.com/reg/1"}
	a := &acmeAccount{Registration: reg}
	assert.Equal(t, reg, a.GetRegistration())
}

func TestAcmeAccount_GetRegistration_Nil(t *testing.T) {
	a := &acmeAccount{}
	assert.Nil(t, a.GetRegistration())
}

func TestAcmeAccount_GetPrivateKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	a := &acmeAccount{Key: key}
	assert.Equal(t, key, a.GetPrivateKey())
}

func TestAcmeAccount_GetPrivateKey_Nil(t *testing.T) {
	a := &acmeAccount{}
	assert.Nil(t, a.GetPrivateKey())
}

// --- atomicWriteFile tests ---

func TestAtomicWriteFile_Success(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "test.txt")
	data := []byte("hello world")

	err := atomicWriteFile(target, data, 0o644)
	require.NoError(t, err)

	got, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, data, got)

	info, err := os.Stat(target)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), info.Mode().Perm())
}

func TestAtomicWriteFile_Overwrites(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "test.txt")

	require.NoError(t, os.WriteFile(target, []byte("old"), 0o600))

	err := atomicWriteFile(target, []byte("new"), 0o600)
	require.NoError(t, err)

	got, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, []byte("new"), got)
}

func TestAtomicWriteFile_EmptyData(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "empty.txt")

	err := atomicWriteFile(target, []byte{}, 0o600)
	require.NoError(t, err)

	got, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestAtomicWriteFile_LargeData(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "large.bin")

	data := make([]byte, 1024*1024) // 1 MB
	for i := range data {
		data[i] = byte(i % 256)
	}

	err := atomicWriteFile(target, data, 0o600)
	require.NoError(t, err)

	got, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, data, got)
}

func TestAtomicWriteFile_NonexistentDir(t *testing.T) {
	target := filepath.Join(t.TempDir(), "no", "such", "dir", "file.txt")

	err := atomicWriteFile(target, []byte("data"), 0o600)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "creating temp file")
}

func TestAtomicWriteFile_Permissions(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name string
		perm os.FileMode
	}{
		{"owner-rw", 0o600},
		{"owner-r", 0o400},
		{"all-r", 0o444},
		{"owner-rwx", 0o700},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := filepath.Join(dir, tt.name+".txt")
			err := atomicWriteFile(target, []byte("test"), tt.perm)
			require.NoError(t, err)

			info, err := os.Stat(target)
			require.NoError(t, err)
			assert.Equal(t, tt.perm, info.Mode().Perm())
		})
	}
}

// --- writeCertificate tests ---

func TestWriteCertificate_Success(t *testing.T) {
	tlsCfg := testTLSConfig(t)

	m := &Manager{
		tlsCfg: tlsCfg,
		log:    testLogger(),
	}

	certPEM, keyPEM := generateTestCert(t, time.Now().Add(90*24*time.Hour))
	res := &certificate.Resource{
		Domain:      "test.example.com",
		Certificate: certPEM,
		PrivateKey:  keyPEM,
	}

	err := m.writeCertificate(res)
	require.NoError(t, err)

	gotCert, err := os.ReadFile(tlsCfg.CertPath)
	require.NoError(t, err)
	assert.Equal(t, certPEM, gotCert)

	gotKey, err := os.ReadFile(tlsCfg.KeyPath)
	require.NoError(t, err)
	assert.Equal(t, keyPEM, gotKey)
}

func TestWriteCertificate_CreatesDirectories(t *testing.T) {
	dir := t.TempDir()
	tlsCfg := config.TLSConfig{
		CertPath: filepath.Join(dir, "certs", "sub", "cert.pem"),
		KeyPath:  filepath.Join(dir, "keys", "sub", "key.pem"),
	}

	m := &Manager{
		tlsCfg: tlsCfg,
		log:    testLogger(),
	}

	certPEM, keyPEM := generateTestCert(t, time.Now().Add(90*24*time.Hour))
	res := &certificate.Resource{
		Domain:      "test.example.com",
		Certificate: certPEM,
		PrivateKey:  keyPEM,
	}

	err := m.writeCertificate(res)
	require.NoError(t, err)

	// Verify directories were created
	_, err = os.Stat(filepath.Dir(tlsCfg.CertPath))
	require.NoError(t, err)
	_, err = os.Stat(filepath.Dir(tlsCfg.KeyPath))
	require.NoError(t, err)
}

func TestWriteCertificate_FilePermissions(t *testing.T) {
	tlsCfg := testTLSConfig(t)

	m := &Manager{
		tlsCfg: tlsCfg,
		log:    testLogger(),
	}

	certPEM, keyPEM := generateTestCert(t, time.Now().Add(90*24*time.Hour))
	res := &certificate.Resource{
		Domain:      "test.example.com",
		Certificate: certPEM,
		PrivateKey:  keyPEM,
	}

	err := m.writeCertificate(res)
	require.NoError(t, err)

	certInfo, err := os.Stat(tlsCfg.CertPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), certInfo.Mode().Perm())

	keyInfo, err := os.Stat(tlsCfg.KeyPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), keyInfo.Mode().Perm())
}

// --- loadOrCreateAccount tests ---

func TestLoadOrCreateAccount_CreatesNew(t *testing.T) {
	acmeCfg := testACMEConfig(t)
	tlsCfg := testTLSConfig(t)

	m := &Manager{
		cfg:    acmeCfg,
		tlsCfg: tlsCfg,
		log:    testLogger(),
	}

	account, err := m.loadOrCreateAccount()
	require.NoError(t, err)
	assert.Equal(t, acmeCfg.Email, account.Email)
	assert.NotNil(t, account.Key)
	assert.NotEmpty(t, account.KeyPEM)
	assert.Nil(t, account.Registration)

	// Verify it was persisted
	_, err = os.Stat(m.accountFilePath())
	require.NoError(t, err)
}

func TestLoadOrCreateAccount_LoadsExisting(t *testing.T) {
	acmeCfg := testACMEConfig(t)
	tlsCfg := testTLSConfig(t)

	m := &Manager{
		cfg:    acmeCfg,
		tlsCfg: tlsCfg,
		log:    testLogger(),
	}

	// Create account first
	original, err := m.loadOrCreateAccount()
	require.NoError(t, err)

	// Load it again
	loaded, err := m.loadOrCreateAccount()
	require.NoError(t, err)

	assert.Equal(t, original.Email, loaded.Email)
	assert.Equal(t, original.KeyPEM, loaded.KeyPEM)

	// Verify the keys are functionally equivalent
	origECKey, ok := original.Key.(*ecdsa.PrivateKey)
	require.True(t, ok)
	loadedECKey, ok := loaded.Key.(*ecdsa.PrivateKey)
	require.True(t, ok)
	assert.True(t, origECKey.Equal(loadedECKey))
}

func TestLoadOrCreateAccount_InvalidJSON(t *testing.T) {
	acmeCfg := testACMEConfig(t)
	tlsCfg := testTLSConfig(t)

	m := &Manager{
		cfg:    acmeCfg,
		tlsCfg: tlsCfg,
		log:    testLogger(),
	}

	// Write invalid JSON to the account file
	require.NoError(t, os.WriteFile(m.accountFilePath(), []byte("{invalid"), 0o600))

	_, err := m.loadOrCreateAccount()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing ACME account file")
}

func TestLoadOrCreateAccount_InvalidPEM(t *testing.T) {
	acmeCfg := testACMEConfig(t)
	tlsCfg := testTLSConfig(t)

	m := &Manager{
		cfg:    acmeCfg,
		tlsCfg: tlsCfg,
		log:    testLogger(),
	}

	// Write a valid JSON with invalid PEM key
	account := acmeAccount{
		Email:  "test@example.com",
		KeyPEM: []byte("not a valid PEM"),
	}
	data, err := json.Marshal(account)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(m.accountFilePath(), data, 0o600))

	_, err = m.loadOrCreateAccount()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode PEM key")
}

func TestLoadOrCreateAccount_InvalidKeyBytes(t *testing.T) {
	acmeCfg := testACMEConfig(t)
	tlsCfg := testTLSConfig(t)

	m := &Manager{
		cfg:    acmeCfg,
		tlsCfg: tlsCfg,
		log:    testLogger(),
	}

	// Write valid JSON with valid PEM structure but garbage key bytes
	badPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: []byte("not a real key"),
	})
	account := acmeAccount{
		Email:  "test@example.com",
		KeyPEM: badPEM,
	}
	data, err := json.Marshal(account)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(m.accountFilePath(), data, 0o600))

	_, err = m.loadOrCreateAccount()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing account private key")
}

func TestLoadOrCreateAccount_WithRegistration(t *testing.T) {
	acmeCfg := testACMEConfig(t)
	tlsCfg := testTLSConfig(t)

	m := &Manager{
		cfg:    acmeCfg,
		tlsCfg: tlsCfg,
		log:    testLogger(),
	}

	// Create an account, add registration, save, then reload
	account, err := m.loadOrCreateAccount()
	require.NoError(t, err)

	account.Registration = &registration.Resource{
		URI: "https://acme.example.com/acct/1",
	}
	require.NoError(t, m.saveAccount(account))

	loaded, err := m.loadOrCreateAccount()
	require.NoError(t, err)
	require.NotNil(t, loaded.Registration)
	assert.Equal(t, "https://acme.example.com/acct/1", loaded.Registration.URI)
}

// --- saveAccount tests ---

func TestSaveAccount_CreatesDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "acme")
	acmeCfg := testACMEConfig(t)
	acmeCfg.StoragePath = dir

	m := &Manager{
		cfg: acmeCfg,
		log: testLogger(),
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	account := &acmeAccount{
		Email:  "test@example.com",
		Key:    key,
		KeyPEM: keyPEM,
	}

	err = m.saveAccount(account)
	require.NoError(t, err)

	// Verify directory was created with proper permissions
	info, err := os.Stat(dir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestSaveAccount_RoundTrip(t *testing.T) {
	acmeCfg := testACMEConfig(t)

	m := &Manager{
		cfg: acmeCfg,
		log: testLogger(),
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	original := &acmeAccount{
		Email:  "roundtrip@example.com",
		Key:    key,
		KeyPEM: keyPEM,
		Registration: &registration.Resource{
			URI: "https://acme.example.com/acct/42",
		},
	}

	err = m.saveAccount(original)
	require.NoError(t, err)

	// Read back the file and verify JSON structure
	data, err := os.ReadFile(m.accountFilePath())
	require.NoError(t, err)

	var loaded acmeAccount
	require.NoError(t, json.Unmarshal(data, &loaded))
	assert.Equal(t, "roundtrip@example.com", loaded.Email)
	assert.Equal(t, original.KeyPEM, loaded.KeyPEM)
	assert.Equal(t, "https://acme.example.com/acct/42", loaded.Registration.URI)
}

func TestSaveAccount_FilePermissions(t *testing.T) {
	acmeCfg := testACMEConfig(t)

	m := &Manager{
		cfg: acmeCfg,
		log: testLogger(),
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	account := &acmeAccount{
		Email:  "test@example.com",
		Key:    key,
		KeyPEM: keyPEM,
	}

	err = m.saveAccount(account)
	require.NoError(t, err)

	info, err := os.Stat(m.accountFilePath())
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

// --- NewManager tests ---

func TestNewManager_WithObtainFunc(t *testing.T) {
	acmeCfg := testACMEConfig(t)
	tlsCfg := testTLSConfig(t)

	called := false
	customObtain := func(_ context.Context, _ []string) (*certificate.Resource, error) {
		called = true
		certPEM, keyPEM := generateTestCert(t, time.Now().Add(90*24*time.Hour))
		return &certificate.Resource{
			Domain:      "test.example.com",
			Certificate: certPEM,
			PrivateKey:  keyPEM,
		}, nil
	}

	m, err := NewManager(acmeCfg, tlsCfg, testLogger(), nil, WithObtainFunc(customObtain))
	require.NoError(t, err)
	require.NotNil(t, m)

	// Verify the custom obtain function is used
	err = m.ObtainCertificate(context.Background())
	require.NoError(t, err)
	assert.True(t, called)
}

func TestNewManager_StoresOnRenew(t *testing.T) {
	acmeCfg := testACMEConfig(t)
	tlsCfg := testTLSConfig(t)

	renewCalled := false
	onRenew := func() error {
		renewCalled = true
		return nil
	}

	m, err := NewManager(acmeCfg, tlsCfg, testLogger(), onRenew,
		WithObtainFunc(mockObtain(t, time.Now().Add(90*24*time.Hour))))
	require.NoError(t, err)
	assert.NotNil(t, m.onRenew)

	// Trigger the callback
	err = m.onRenew()
	require.NoError(t, err)
	assert.True(t, renewCalled)
}

func TestNewManager_NilOnRenew(t *testing.T) {
	acmeCfg := testACMEConfig(t)
	tlsCfg := testTLSConfig(t)

	m, err := NewManager(acmeCfg, tlsCfg, testLogger(), nil,
		WithObtainFunc(mockObtain(t, time.Now().Add(90*24*time.Hour))))
	require.NoError(t, err)
	assert.Nil(t, m.onRenew)
}

func TestNewManager_ChannelsInitialized(t *testing.T) {
	acmeCfg := testACMEConfig(t)
	tlsCfg := testTLSConfig(t)

	m, err := NewManager(acmeCfg, tlsCfg, testLogger(), nil,
		WithObtainFunc(mockObtain(t, time.Now().Add(90*24*time.Hour))))
	require.NoError(t, err)
	assert.NotNil(t, m.stopCh)
	assert.NotNil(t, m.stopped)
	assert.False(t, m.started)
}

// --- RenewIfNeeded additional error path tests ---

func TestRenewIfNeeded_InvalidPEMOnDisk(t *testing.T) {
	acmeCfg := testACMEConfig(t)
	tlsCfg := testTLSConfig(t)

	// Write invalid PEM data as the cert
	require.NoError(t, os.WriteFile(tlsCfg.CertPath, []byte("not a PEM"), 0o600))

	m, err := NewManager(acmeCfg, tlsCfg, testLogger(), nil,
		WithObtainFunc(mockObtain(t, time.Now().Add(90*24*time.Hour))))
	require.NoError(t, err)

	_, err = m.RenewIfNeeded(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode PEM certificate")
}

func TestRenewIfNeeded_InvalidCertBytes(t *testing.T) {
	acmeCfg := testACMEConfig(t)
	tlsCfg := testTLSConfig(t)

	// Write valid PEM but with garbage DER bytes
	badCert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("not a real certificate"),
	})
	require.NoError(t, os.WriteFile(tlsCfg.CertPath, badCert, 0o600))

	m, err := NewManager(acmeCfg, tlsCfg, testLogger(), nil,
		WithObtainFunc(mockObtain(t, time.Now().Add(90*24*time.Hour))))
	require.NoError(t, err)

	_, err = m.RenewIfNeeded(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing certificate")
}

func TestRenewIfNeeded_ObtainError(t *testing.T) {
	acmeCfg := testACMEConfig(t)
	tlsCfg := testTLSConfig(t)

	// Write an expiring cert
	certPEM, keyPEM := generateTestCert(t, time.Now().Add(1*24*time.Hour))
	require.NoError(t, os.WriteFile(tlsCfg.CertPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(tlsCfg.KeyPath, keyPEM, 0o600))

	errObtain := errors.New("obtain failed")
	failObtain := func(_ context.Context, _ []string) (*certificate.Resource, error) {
		return nil, errObtain
	}

	m, err := NewManager(acmeCfg, tlsCfg, testLogger(), nil, WithObtainFunc(failObtain))
	require.NoError(t, err)

	_, err = m.RenewIfNeeded(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "obtain failed")
}

func TestRenewIfNeeded_OnRenewError(t *testing.T) {
	acmeCfg := testACMEConfig(t)
	tlsCfg := testTLSConfig(t)

	// Write an expiring cert
	certPEM, keyPEM := generateTestCert(t, time.Now().Add(1*24*time.Hour))
	require.NoError(t, os.WriteFile(tlsCfg.CertPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(tlsCfg.KeyPath, keyPEM, 0o600))

	errCallback := errors.New("callback error")
	m, err := NewManager(acmeCfg, tlsCfg, testLogger(), func() error {
		return errCallback
	}, WithObtainFunc(mockObtain(t, time.Now().Add(90*24*time.Hour))))
	require.NoError(t, err)

	renewed, err := m.RenewIfNeeded(context.Background())
	assert.True(t, renewed)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "calling renewal callback")
}

func TestRenewIfNeeded_NilOnRenewCallback(t *testing.T) {
	acmeCfg := testACMEConfig(t)
	tlsCfg := testTLSConfig(t)

	// Write an expiring cert
	certPEM, keyPEM := generateTestCert(t, time.Now().Add(1*24*time.Hour))
	require.NoError(t, os.WriteFile(tlsCfg.CertPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(tlsCfg.KeyPath, keyPEM, 0o600))

	// nil onRenew should not panic
	m, err := NewManager(acmeCfg, tlsCfg, testLogger(), nil,
		WithObtainFunc(mockObtain(t, time.Now().Add(90*24*time.Hour))))
	require.NoError(t, err)

	renewed, err := m.RenewIfNeeded(context.Background())
	require.NoError(t, err)
	assert.True(t, renewed)
}

// --- runRenewalCheck tests ---

func TestRunRenewalCheck_Success_NoRenewal(t *testing.T) {
	acmeCfg := testACMEConfig(t)
	tlsCfg := testTLSConfig(t)

	notAfter := time.Now().Add(90 * 24 * time.Hour)
	certPEM, keyPEM := generateTestCert(t, notAfter)
	require.NoError(t, os.WriteFile(tlsCfg.CertPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(tlsCfg.KeyPath, keyPEM, 0o600))

	m, err := NewManager(acmeCfg, tlsCfg, testLogger(), nil,
		WithObtainFunc(mockObtain(t, notAfter)))
	require.NoError(t, err)

	// Should not panic or error (logs internally)
	m.runRenewalCheck(context.Background())
}

func TestRunRenewalCheck_Success_WithRenewal(t *testing.T) {
	acmeCfg := testACMEConfig(t)
	tlsCfg := testTLSConfig(t)

	// Write an expiring cert
	certPEM, keyPEM := generateTestCert(t, time.Now().Add(1*24*time.Hour))
	require.NoError(t, os.WriteFile(tlsCfg.CertPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(tlsCfg.KeyPath, keyPEM, 0o600))

	renewCalled := false
	m, err := NewManager(acmeCfg, tlsCfg, testLogger(), func() error {
		renewCalled = true
		return nil
	}, WithObtainFunc(mockObtain(t, time.Now().Add(90*24*time.Hour))))
	require.NoError(t, err)

	m.runRenewalCheck(context.Background())
	assert.True(t, renewCalled)
}

func TestRunRenewalCheck_ErrorPath(t *testing.T) {
	acmeCfg := testACMEConfig(t)
	tlsCfg := testTLSConfig(t)
	// No cert on disk so RenewIfNeeded will fail

	m, err := NewManager(acmeCfg, tlsCfg, testLogger(), nil,
		WithObtainFunc(mockObtain(t, time.Now().Add(90*24*time.Hour))))
	require.NoError(t, err)

	// Should not panic (logs error internally)
	m.runRenewalCheck(context.Background())
}

// --- ObtainCertificate error path tests ---

func TestObtainCertificate_ObtainFuncError(t *testing.T) {
	acmeCfg := testACMEConfig(t)
	tlsCfg := testTLSConfig(t)

	errObtain := errors.New("simulated obtain failure")
	m, err := NewManager(acmeCfg, tlsCfg, testLogger(), nil,
		WithObtainFunc(func(_ context.Context, _ []string) (*certificate.Resource, error) {
			return nil, errObtain
		}))
	require.NoError(t, err)

	err = m.ObtainCertificate(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "simulated obtain failure")
}

// --- WithObtainFunc option test ---

func TestWithObtainFunc_OverridesDefault(t *testing.T) {
	called := false
	fn := func(_ context.Context, _ []string) (*certificate.Resource, error) {
		called = true
		return &certificate.Resource{}, nil
	}

	acmeCfg := testACMEConfig(t)
	tlsCfg := testTLSConfig(t)

	m, err := NewManager(acmeCfg, tlsCfg, testLogger(), nil, WithObtainFunc(fn))
	require.NoError(t, err)

	// The obtain func should be our custom one, not buildObtainFunc
	_, _ = m.obtain(context.Background(), []string{"example.com"})
	assert.True(t, called)
}

// --- Edge case: renewal loop with expiring cert triggers renewal ---

// --- NewManager without WithObtainFunc exercises buildObtainFunc ---

func TestNewManager_BuildObtainFunc_LoadAccountError(t *testing.T) {
	acmeCfg := testACMEConfig(t)
	tlsCfg := testTLSConfig(t)

	// Write invalid JSON as account file so loadOrCreateAccount fails inside buildObtainFunc
	require.NoError(t, os.WriteFile(filepath.Join(acmeCfg.StoragePath, "account.json"), []byte("{bad"), 0o600))

	_, err := NewManager(acmeCfg, tlsCfg, testLogger(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "loading ACME account")
}

func TestNewManager_BuildObtainFunc_InvalidDirectoryURL(t *testing.T) {
	acmeCfg := testACMEConfig(t)
	acmeCfg.DirectoryURL = "not-a-url"
	tlsCfg := testTLSConfig(t)

	// This will succeed in loadOrCreateAccount (creates new) but fail
	// when creating the lego client with an invalid directory URL
	_, err := NewManager(acmeCfg, tlsCfg, testLogger(), nil)
	// The error could be from lego client or cloudflare provider
	require.Error(t, err)
}

func TestNewManager_BuildObtainFunc_BadEnvVar(t *testing.T) {
	acmeCfg := testACMEConfig(t)
	acmeCfg.DNS.Cloudflare.APIToken = "${NONEXISTENT_ACME_TEST_VAR}"
	tlsCfg := testTLSConfig(t)

	_, err := NewManager(acmeCfg, tlsCfg, testLogger(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expanding Cloudflare API token")
}

func TestNewManager_BuildObtainFunc_EmptyToken(t *testing.T) {
	acmeCfg := testACMEConfig(t)
	acmeCfg.DNS.Cloudflare.APIToken = ""
	tlsCfg := testTLSConfig(t)

	// Empty token should cause provider creation to fail
	_, err := NewManager(acmeCfg, tlsCfg, testLogger(), nil)
	require.Error(t, err)
}

// --- atomicWriteFile error cleanup paths ---

func TestAtomicWriteFile_ReadOnlyDir(t *testing.T) {
	dir := t.TempDir()
	roDir := filepath.Join(dir, "readonly")
	require.NoError(t, os.Mkdir(roDir, 0o500))
	t.Cleanup(func() {
		// Restore write permission so cleanup can remove the dir
		_ = os.Chmod(roDir, 0o700)
	})

	target := filepath.Join(roDir, "file.txt")
	err := atomicWriteFile(target, []byte("data"), 0o600)
	// On macOS, CreateTemp in a read-only dir should fail
	require.Error(t, err)
}

// --- writeCertificate error paths ---

func TestWriteCertificate_BadCertDir(t *testing.T) {
	dir := t.TempDir()
	// Use a file (not directory) as the parent path to trigger MkdirAll failure
	blocker := filepath.Join(dir, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))

	tlsCfg := config.TLSConfig{
		CertPath: filepath.Join(blocker, "sub", "cert.pem"),
		KeyPath:  filepath.Join(dir, "key.pem"),
	}

	m := &Manager{
		tlsCfg: tlsCfg,
		log:    testLogger(),
	}

	certPEM, keyPEM := generateTestCert(t, time.Now().Add(90*24*time.Hour))
	res := &certificate.Resource{
		Domain:      "test.example.com",
		Certificate: certPEM,
		PrivateKey:  keyPEM,
	}

	err := m.writeCertificate(res)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "creating certificate directory")
}

func TestWriteCertificate_BadKeyDir(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))

	tlsCfg := config.TLSConfig{
		CertPath: filepath.Join(dir, "cert.pem"),
		KeyPath:  filepath.Join(blocker, "sub", "key.pem"),
	}

	m := &Manager{
		tlsCfg: tlsCfg,
		log:    testLogger(),
	}

	certPEM, keyPEM := generateTestCert(t, time.Now().Add(90*24*time.Hour))
	res := &certificate.Resource{
		Domain:      "test.example.com",
		Certificate: certPEM,
		PrivateKey:  keyPEM,
	}

	err := m.writeCertificate(res)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "creating key directory")
}

func TestWriteCertificate_KeyWriteError(t *testing.T) {
	dir := t.TempDir()

	// Create the key directory as read-only so atomicWriteFile for key fails
	keyDir := filepath.Join(dir, "keys")
	require.NoError(t, os.Mkdir(keyDir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(keyDir, 0o700) })

	tlsCfg := config.TLSConfig{
		CertPath: filepath.Join(dir, "cert.pem"),
		KeyPath:  filepath.Join(keyDir, "key.pem"),
	}

	m := &Manager{
		tlsCfg: tlsCfg,
		log:    testLogger(),
	}

	certPEM, keyPEM := generateTestCert(t, time.Now().Add(90*24*time.Hour))
	res := &certificate.Resource{
		Domain:      "test.example.com",
		Certificate: certPEM,
		PrivateKey:  keyPEM,
	}

	err := m.writeCertificate(res)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "writing key file")
}

// --- saveAccount error paths ---

func TestSaveAccount_BadStoragePath(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))

	acmeCfg := testACMEConfig(t)
	acmeCfg.StoragePath = filepath.Join(blocker, "sub")

	m := &Manager{
		cfg: acmeCfg,
		log: testLogger(),
	}

	account := &acmeAccount{
		Email:  "test@example.com",
		KeyPEM: []byte("test"),
	}

	err := m.saveAccount(account)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "creating ACME storage directory")
}

// --- loadOrCreateAccount: non-ENOENT read error ---

func TestLoadOrCreateAccount_PermissionDenied(t *testing.T) {
	acmeCfg := testACMEConfig(t)
	tlsCfg := testTLSConfig(t)

	m := &Manager{
		cfg:    acmeCfg,
		tlsCfg: tlsCfg,
		log:    testLogger(),
	}

	// Write account file but make it unreadable
	acctPath := m.accountFilePath()
	require.NoError(t, os.WriteFile(acctPath, []byte("{}"), 0o000))
	t.Cleanup(func() { _ = os.Chmod(acctPath, 0o600) })

	_, err := m.loadOrCreateAccount()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading ACME account file")
}

// --- loadOrCreateAccount: save error on new account ---

func TestLoadOrCreateAccount_SaveError(t *testing.T) {
	dir := t.TempDir()

	// Create the storage directory as read-only so os.WriteFile inside
	// saveAccount fails, but os.ReadFile sees ENOENT (no account.json),
	// causing loadOrCreateAccount to try creating a new account and then
	// fail on save.
	storageDir := filepath.Join(dir, "acme-storage")
	require.NoError(t, os.Mkdir(storageDir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(storageDir, 0o700) })

	acmeCfg := testACMEConfig(t)
	acmeCfg.StoragePath = storageDir

	m := &Manager{
		cfg: acmeCfg,
		log: testLogger(),
	}

	_, err := m.loadOrCreateAccount()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "saving new ACME account")
}

func TestRenewalLoop_ExpiringCert_TriggersRenewal(t *testing.T) {
	acmeCfg := testACMEConfig(t)
	acmeCfg.CheckInterval = 60 // won't tick during test
	tlsCfg := testTLSConfig(t)

	// Write an expiring cert (within renewal window)
	certPEM, keyPEM := generateTestCert(t, time.Now().Add(2*24*time.Hour))
	require.NoError(t, os.WriteFile(tlsCfg.CertPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(tlsCfg.KeyPath, keyPEM, 0o600))

	renewCalled := false
	m, err := NewManager(acmeCfg, tlsCfg, testLogger(), func() error {
		renewCalled = true
		return nil
	}, WithObtainFunc(mockObtain(t, time.Now().Add(90*24*time.Hour))))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	m.Start(ctx)

	// The immediate check in renewalLoop should trigger renewal
	// Wait briefly for the goroutine to run its initial check
	time.Sleep(200 * time.Millisecond)

	cancel()
	<-m.stopped

	assert.True(t, renewCalled, "renewal should have been triggered by the immediate check")
}
