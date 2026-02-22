// Package acme provides ACME certificate lifecycle management using DNS-01
// challenges via Cloudflare. It handles certificate acquisition, background
// renewal, and hot-swap via a reload callback.
package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	legocf "github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
	"github.com/samber/oops"

	legoclient "github.com/go-acme/lego/v4/lego"

	"github.com/fzymgc-house/router-hosts/internal/config"
)

// acmeAccount implements registration.User for lego.
type acmeAccount struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration"`
	Key          crypto.PrivateKey      `json:"-"`
	KeyPEM       []byte                 `json:"key_pem"`
}

// GetEmail implements registration.User.
func (a *acmeAccount) GetEmail() string { return a.Email }

// GetRegistration implements registration.User.
func (a *acmeAccount) GetRegistration() *registration.Resource { return a.Registration }

// GetPrivateKey implements registration.User.
func (a *acmeAccount) GetPrivateKey() crypto.PrivateKey { return a.Key }

// obtainFunc abstracts certificate obtain/renew for testing.
type obtainFunc func(ctx context.Context, domains []string) (*certificate.Resource, error)

// Manager handles ACME certificate lifecycle.
type Manager struct {
	cfg     config.ACMEConfig
	tlsCfg  config.TLSConfig
	log     *slog.Logger
	onRenew func() error

	obtain obtainFunc

	mu      sync.Mutex
	started bool
	stopCh  chan struct{}
	stopped chan struct{}
}

// Option configures a Manager.
type Option func(*Manager)

// WithObtainFunc overrides the certificate obtain function (for testing).
func WithObtainFunc(fn obtainFunc) Option {
	return func(m *Manager) {
		m.obtain = fn
	}
}

// NewManager creates an ACME manager from config.
// The onRenew callback is called after successfully writing new certificates.
func NewManager(acmeCfg config.ACMEConfig, tlsCfg config.TLSConfig, logger *slog.Logger, onRenew func() error, opts ...Option) (*Manager, error) {
	m := &Manager{
		cfg:     acmeCfg,
		tlsCfg:  tlsCfg,
		log:     logger,
		onRenew: onRenew,
		stopCh:  make(chan struct{}),
		stopped: make(chan struct{}),
	}

	for _, o := range opts {
		o(m)
	}

	if m.obtain == nil {
		fn, err := m.buildObtainFunc()
		if err != nil {
			return nil, err
		}
		m.obtain = fn
	}

	return m, nil
}

// buildObtainFunc creates the real lego-based obtain function.
func (m *Manager) buildObtainFunc() (obtainFunc, error) {
	account, err := m.loadOrCreateAccount()
	if err != nil {
		return nil, oops.Wrapf(err, "loading ACME account")
	}

	legoCfg := legoclient.NewConfig(account)
	legoCfg.CADirURL = m.cfg.DirectoryURL
	legoCfg.Certificate.KeyType = "P256"

	client, err := legoclient.NewClient(legoCfg)
	if err != nil {
		return nil, oops.Wrapf(err, "creating ACME client")
	}

	// Expand the API token from environment
	apiToken, err := config.ExpandEnvVars(m.cfg.DNS.Cloudflare.APIToken)
	if err != nil {
		return nil, oops.Wrapf(err, "expanding Cloudflare API token")
	}

	cfCfg := legocf.NewDefaultConfig()
	cfCfg.AuthToken = apiToken

	provider, err := legocf.NewDNSProviderConfig(cfCfg)
	if err != nil {
		return nil, oops.Wrapf(err, "creating Cloudflare DNS provider")
	}

	if err := client.Challenge.SetDNS01Provider(provider); err != nil {
		return nil, oops.Wrapf(err, "setting DNS-01 provider")
	}

	// Register if needed
	if account.Registration == nil {
		reg, regErr := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if regErr != nil {
			return nil, oops.Wrapf(regErr, "registering ACME account")
		}
		account.Registration = reg
		if saveErr := m.saveAccount(account); saveErr != nil {
			return nil, oops.Wrapf(saveErr, "saving ACME account after registration")
		}
	}

	return func(_ context.Context, domains []string) (*certificate.Resource, error) {
		req := certificate.ObtainRequest{
			Domains: domains,
			Bundle:  true,
		}
		res, obtainErr := client.Certificate.Obtain(req)
		if obtainErr != nil {
			return nil, oops.Wrapf(obtainErr, "obtaining certificate")
		}
		return res, nil
	}, nil
}

// accountFilePath returns the path to the ACME account JSON file.
func (m *Manager) accountFilePath() string {
	return filepath.Join(m.cfg.StoragePath, "account.json")
}

// loadOrCreateAccount loads an existing ACME account or creates a new one.
func (m *Manager) loadOrCreateAccount() (*acmeAccount, error) {
	path := m.accountFilePath()

	data, err := os.ReadFile(path)
	if err == nil {
		var account acmeAccount
		if jsonErr := json.Unmarshal(data, &account); jsonErr != nil {
			return nil, oops.Wrapf(jsonErr, "parsing ACME account file")
		}

		block, _ := pem.Decode(account.KeyPEM)
		if block == nil {
			return nil, oops.Errorf("failed to decode PEM key from account file")
		}
		key, keyErr := x509.ParseECPrivateKey(block.Bytes)
		if keyErr != nil {
			return nil, oops.Wrapf(keyErr, "parsing account private key")
		}
		account.Key = key

		m.log.Info("loaded existing ACME account", "email", account.Email)
		return &account, nil
	}

	if !os.IsNotExist(err) {
		return nil, oops.Wrapf(err, "reading ACME account file")
	}

	// Create new account
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, oops.Wrapf(err, "generating account key")
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, oops.Wrapf(err, "marshaling account key")
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	account := &acmeAccount{
		Email:  m.cfg.Email,
		Key:    key,
		KeyPEM: keyPEM,
	}

	// Persist key immediately so it survives crashes before registration completes.
	if err := m.saveAccount(account); err != nil {
		return nil, oops.Wrapf(err, "saving new ACME account")
	}

	m.log.Info("created new ACME account", "email", m.cfg.Email)
	return account, nil
}

// saveAccount persists the ACME account to disk.
func (m *Manager) saveAccount(account *acmeAccount) error {
	if err := os.MkdirAll(filepath.Dir(m.accountFilePath()), 0o700); err != nil {
		return oops.Wrapf(err, "creating ACME storage directory")
	}

	data, err := json.MarshalIndent(account, "", "  ")
	if err != nil {
		return oops.Wrapf(err, "marshaling ACME account")
	}

	if err := os.WriteFile(m.accountFilePath(), data, 0o600); err != nil {
		return oops.Wrapf(err, "writing ACME account file")
	}

	return nil
}

// ObtainCertificate requests a new certificate from the ACME CA
// and writes it to the paths specified in TLSConfig.
func (m *Manager) ObtainCertificate(ctx context.Context) error {
	m.log.Info("obtaining certificate", "domains", m.cfg.Domains)

	res, err := m.obtain(ctx, m.cfg.Domains)
	if err != nil {
		return err
	}

	return m.writeCertificate(res)
}

// writeCertificate atomically writes the certificate and key to disk.
// Both files are written to temporary paths first, then renamed to avoid
// partial writes leaving mismatched cert+key pairs.
func (m *Manager) writeCertificate(res *certificate.Resource) error {
	certDir := filepath.Dir(m.tlsCfg.CertPath)
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		return oops.Wrapf(err, "creating certificate directory")
	}

	keyDir := filepath.Dir(m.tlsCfg.KeyPath)
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		return oops.Wrapf(err, "creating key directory")
	}

	// Write to temp files first, then rename for atomicity.
	if err := atomicWriteFile(m.tlsCfg.KeyPath, res.PrivateKey, 0o600); err != nil {
		return oops.Wrapf(err, "writing key file")
	}

	if err := atomicWriteFile(m.tlsCfg.CertPath, res.Certificate, 0o600); err != nil {
		return oops.Wrapf(err, "writing certificate file")
	}

	m.log.Info("certificate written",
		"cert_path", m.tlsCfg.CertPath,
		"key_path", m.tlsCfg.KeyPath,
		"domain", res.Domain,
	)

	return nil
}

// atomicWriteFile writes data to a temporary file in the same directory as
// target, then renames it to target. This ensures the target file is never
// in a partially-written state.
func atomicWriteFile(target string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(target)
	tmp, err := os.CreateTemp(dir, filepath.Base(target)+".tmp.*")
	if err != nil {
		return oops.Wrapf(err, "creating temp file for %s", target)
	}
	tmpPath := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return oops.Wrapf(err, "writing temp file")
	}

	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return oops.Wrapf(err, "syncing temp file")
	}

	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return oops.Wrapf(err, "closing temp file")
	}

	if err := os.Chmod(tmpPath, perm); err != nil {
		_ = os.Remove(tmpPath)
		return oops.Wrapf(err, "setting permissions on temp file")
	}

	if err := os.Rename(tmpPath, target); err != nil {
		_ = os.Remove(tmpPath)
		return oops.Wrapf(err, "renaming temp file to %s", target)
	}

	return nil
}

// RenewIfNeeded checks the current certificate and renews if within the renewal window.
// Returns true if a renewal was performed.
func (m *Manager) RenewIfNeeded(ctx context.Context) (bool, error) {
	certPEM, err := os.ReadFile(m.tlsCfg.CertPath)
	if err != nil {
		return false, oops.Wrapf(err, "reading certificate for renewal check")
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false, oops.Errorf("failed to decode PEM certificate at %s", m.tlsCfg.CertPath)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, oops.Wrapf(err, "parsing certificate for renewal check")
	}

	renewalThreshold := time.Now().Add(time.Duration(m.cfg.RenewalDays) * 24 * time.Hour)
	if cert.NotAfter.After(renewalThreshold) {
		m.log.Debug("certificate not due for renewal",
			"not_after", cert.NotAfter,
			"renewal_threshold", renewalThreshold,
		)
		return false, nil
	}

	m.log.Info("certificate due for renewal",
		"not_after", cert.NotAfter,
		"renewal_threshold", renewalThreshold,
	)

	if err := m.ObtainCertificate(ctx); err != nil {
		return false, oops.Wrapf(err, "renewing certificate")
	}

	if m.onRenew != nil {
		if err := m.onRenew(); err != nil {
			return true, oops.Wrapf(err, "calling renewal callback")
		}
	}

	return true, nil
}

// Start begins the background renewal goroutine. It runs an immediate renewal
// check before entering the periodic loop. Safe to call only once; subsequent
// calls are no-ops.
func (m *Manager) Start(ctx context.Context) {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return
	}
	m.started = true
	m.mu.Unlock()

	interval := time.Duration(m.cfg.CheckInterval) * time.Second
	m.log.Info("starting ACME renewal loop", "interval", interval)

	go m.renewalLoop(ctx, interval)
}

// renewalLoop runs an immediate check then enters the periodic renewal loop.
func (m *Manager) renewalLoop(ctx context.Context, interval time.Duration) {
	defer close(m.stopped)

	// Immediate check on start so an expired cert is renewed without waiting.
	m.runRenewalCheck(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.runRenewalCheck(ctx)
		case <-m.stopCh:
			m.log.Info("stopping ACME renewal loop")
			return
		case <-ctx.Done():
			m.log.Info("ACME renewal loop cancelled")
			return
		}
	}
}

// runRenewalCheck performs a single renewal check, logging any outcome.
func (m *Manager) runRenewalCheck(ctx context.Context) {
	renewed, err := m.RenewIfNeeded(ctx)
	if err != nil {
		m.log.Error("renewal check failed", "error", err)
	} else if renewed {
		m.log.Info("certificate renewed successfully")
	}
}

// Stop halts the background renewal goroutine and waits for it to finish.
// Safe to call multiple times; no-op if Start was never called.
func (m *Manager) Stop() {
	m.mu.Lock()
	if !m.started {
		m.mu.Unlock()
		return
	}
	select {
	case <-m.stopCh:
		// Already stopped
		m.mu.Unlock()
		return
	default:
		close(m.stopCh)
	}
	m.mu.Unlock()

	<-m.stopped
}
