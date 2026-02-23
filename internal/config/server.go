// Package config provides configuration loading for the router-hosts server
// and client. Server config is loaded from TOML files with the same structure
// as the Rust implementation for compatibility.
package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	// BurntSushi/toml is used instead of go-toml/v2 (referenced in the design
	// spec) because it exposes MetaData.Undecoded() for strict decoding — i.e.,
	// detecting unknown config keys and surfacing them as errors. go-toml/v2
	// does not provide an equivalent API.
	"github.com/BurntSushi/toml"
	"github.com/samber/oops"

	"github.com/fzymgc-house/router-hosts/internal/domain"
)

// Default values for retention policy.
const (
	DefaultMaxSnapshots = 50
	DefaultMaxAgeDays   = 30

	// DefaultExportIntervalSecs is the default OTEL metrics export interval.
	DefaultExportIntervalSecs = 60

	// MaxHookNameLength is the maximum allowed length for hook names.
	MaxHookNameLength = 50

	// DefaultRenewalDays is the number of days before certificate expiry to trigger renewal.
	DefaultRenewalDays = 30

	// DefaultCheckInterval is the interval in seconds between ACME renewal checks (12 hours).
	DefaultCheckInterval = 43200

	// LetsEncryptProductionURL is the default ACME directory URL.
	LetsEncryptProductionURL = "https://acme-v02.api.letsencrypt.org/directory"
)

// Config is the top-level server configuration, loaded from TOML.
type Config struct {
	Server    ServerConfig    `toml:"server"`
	Database  DatabaseConfig  `toml:"database"`
	TLS       TLSConfig       `toml:"tls"`
	Retention RetentionConfig `toml:"retention"`
	Hooks     HooksConfig     `toml:"hooks"`
	Metrics   *MetricsConfig  `toml:"metrics,omitempty"`
}

// ServerConfig holds the core server settings.
type ServerConfig struct {
	BindAddress   string `toml:"bind_address"`
	HostsFilePath string `toml:"hosts_file_path"`
}

// DatabaseConfig holds the database connection settings.
// For Go, we only support SQLite, so this is simplified to a path.
//
// Migration from Rust implementation:
//   - Rust used [database] url = "sqlite:///path/to/db" or database_url = "postgres://..."
//   - Go uses [database] path = "/path/to/db" (SQLite only)
//   - PostgreSQL and DuckDB backends were removed in the Go rewrite
//
// If you have an old config file with [database] url or database_url:
//   - Remove the url/database_url field
//   - Add path = "/path/to/db" (use the local file path from the URL)
//   - For sqlite:///path/to/db → path = "/path/to/db"
//   - For sqlite://path/to/db → path = "path/to/db"
//
// If path is empty or not specified, the default XDG-compliant location
// is used (~/.local/share/router-hosts/hosts.db on Linux,
// ~/Library/Application Support/router-hosts/hosts.db on macOS).
//
// The strict TOML decoder will reject unknown keys (like url or database_url),
// so migrate your config file to use the new schema.
type DatabaseConfig struct {
	Path string `toml:"path"`
}

// TLSConfig holds paths to TLS certificates for mTLS.
type TLSConfig struct {
	CertPath   string      `toml:"cert_path"`
	KeyPath    string      `toml:"key_path"`
	CACertPath string      `toml:"ca_cert_path"`
	ACME       *ACMEConfig `toml:"acme,omitempty"`
}

// ACMEConfig holds ACME certificate automation settings.
type ACMEConfig struct {
	Enabled       bool          `toml:"enabled"`
	DirectoryURL  string        `toml:"directory_url"`
	Email         string        `toml:"email"`
	Domains       []string      `toml:"domains"`
	DNS           ACMEDNSConfig `toml:"dns"`
	RenewalDays   int           `toml:"renewal_days"`
	CheckInterval int           `toml:"check_interval"`
	StoragePath   string        `toml:"storage_path"`
}

// ACMEDNSConfig holds DNS provider settings for DNS-01 challenges.
type ACMEDNSConfig struct {
	Provider   string         `toml:"provider"`
	Cloudflare *CloudflareDNS `toml:"cloudflare,omitempty"`
}

// CloudflareDNS holds Cloudflare-specific DNS challenge settings.
type CloudflareDNS struct {
	APIToken string `toml:"api_token"` // supports ${ENV_VAR} expansion
}

// RetentionConfig controls snapshot retention policy.
type RetentionConfig struct {
	MaxSnapshots int `toml:"max_snapshots"`
	MaxAgeDays   int `toml:"max_age_days"`
}

// Validate checks that retention values are positive. Zero and negative values
// are rejected because they would either keep no snapshots or produce undefined
// retention behaviour. Use LoadServerConfig to apply defaults before validating.
func (r *RetentionConfig) Validate() error {
	if r.MaxSnapshots < 0 {
		return oops.Code(domain.CodeValidation).Errorf("config: retention.max_snapshots must be non-negative (got %d)", r.MaxSnapshots)
	}
	if r.MaxAgeDays < 0 {
		return oops.Code(domain.CodeValidation).Errorf("config: retention.max_age_days must be non-negative (got %d)", r.MaxAgeDays)
	}
	return nil
}

// HookDefinition is a named shell command executed on events.
type HookDefinition struct {
	Name    string `toml:"name"`
	Command string `toml:"command"`
}

// HooksConfig holds on-success and on-failure hook definitions.
type HooksConfig struct {
	OnSuccess []HookDefinition `toml:"on_success"`
	OnFailure []HookDefinition `toml:"on_failure"`
}

// OTelConfig holds OpenTelemetry exporter settings.
type OTelConfig struct {
	Endpoint          string            `toml:"endpoint"`
	ServiceName       string            `toml:"service_name"`
	Insecure          bool              `toml:"insecure"`
	CACertFile        string            `toml:"ca_cert_file"`
	ClientCertFile    string            `toml:"client_cert_file"`
	ClientKeyFile     string            `toml:"client_key_file"`
	ExportMetrics     *bool             `toml:"export_metrics,omitempty"`
	ExportTraces      *bool             `toml:"export_traces,omitempty"`
	ExportIntervalSec int               `toml:"export_interval_secs"`
	Headers           map[string]string `toml:"headers"`
}

// MetricsConfig holds observability configuration.
type MetricsConfig struct {
	OTel *OTelConfig `toml:"otel,omitempty"`
}

// DefaultDBPath returns the platform-appropriate default database path.
func DefaultDBPath() (string, error) {
	var dataDir string

	switch runtime.GOOS {
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", oops.Wrapf(err, "determine home directory")
		}
		dataDir = filepath.Join(home, "Library", "Application Support")
	default: // linux and others use XDG
		if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
			dataDir = xdg
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", oops.Wrapf(err, "determine home directory")
			}
			dataDir = filepath.Join(home, ".local", "share")
		}
	}

	return filepath.Join(dataDir, "router-hosts", "hosts.db"), nil
}

// ResolveDBPath returns the effective database path, using the default if none
// is configured.
func (c *DatabaseConfig) ResolveDBPath() (string, error) {
	if c.Path != "" {
		return c.Path, nil
	}
	return DefaultDBPath()
}

// LoadServerConfig reads and validates a server configuration from a TOML file.
func LoadServerConfig(path string) (*Config, error) {
	if err := checkConfigPermissions(path); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, oops.Wrapf(err, "read config file")
	}

	var cfg Config
	meta, err := toml.Decode(string(data), &cfg)
	if err != nil {
		return nil, oops.Wrapf(err, "parse config file")
	}
	if keys := meta.Undecoded(); len(keys) > 0 {
		strs := make([]string, len(keys))
		for i, k := range keys {
			strs[i] = k.String()
		}
		return nil, oops.Code(domain.CodeValidation).Errorf("config: unknown keys: [%s]", strings.Join(strs, ", "))
	}

	// Apply defaults for retention if zero-valued
	if cfg.Retention.MaxSnapshots == 0 {
		cfg.Retention.MaxSnapshots = DefaultMaxSnapshots
	}
	if cfg.Retention.MaxAgeDays == 0 {
		cfg.Retention.MaxAgeDays = DefaultMaxAgeDays
	}

	// Apply ACME defaults
	if cfg.TLS.ACME != nil && cfg.TLS.ACME.Enabled {
		acme := cfg.TLS.ACME
		if acme.DirectoryURL == "" {
			acme.DirectoryURL = LetsEncryptProductionURL
		}
		if acme.RenewalDays == 0 {
			acme.RenewalDays = DefaultRenewalDays
		}
		if acme.CheckInterval == 0 {
			acme.CheckInterval = DefaultCheckInterval
		}
	}

	// Apply OTel defaults
	if cfg.Metrics != nil && cfg.Metrics.OTel != nil {
		otel := cfg.Metrics.OTel
		if otel.ServiceName == "" {
			otel.ServiceName = "router-hosts"
		}
		if otel.ExportMetrics == nil {
			t := true
			otel.ExportMetrics = &t
		}
		if otel.ExportTraces == nil {
			t := true
			otel.ExportTraces = &t
		}
		if otel.ExportIntervalSec == 0 {
			otel.ExportIntervalSec = DefaultExportIntervalSecs
		}
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// validate checks all required fields and hook definitions.
func (c *Config) validate() error {
	if c.Server.BindAddress == "" {
		return oops.Code(domain.CodeValidation).Errorf("config: bind_address is required")
	}
	if c.Server.HostsFilePath == "" {
		return oops.Code(domain.CodeValidation).Errorf("config: hosts_file_path is required")
	}

	if err := c.Hooks.validate(); err != nil {
		return err
	}

	if err := c.TLS.validateACME(); err != nil {
		return err
	}

	if err := c.Retention.Validate(); err != nil {
		return err
	}

	return nil
}

// validateACME checks ACME configuration when enabled.
func (t *TLSConfig) validateACME() error {
	if t.ACME == nil || !t.ACME.Enabled {
		return nil
	}

	acme := t.ACME
	if acme.Email == "" {
		return oops.Code(domain.CodeValidation).Errorf("config: acme.email is required when ACME is enabled")
	}
	if len(acme.Domains) == 0 {
		return oops.Code(domain.CodeValidation).Errorf("config: acme.domains must contain at least one domain when ACME is enabled")
	}
	if acme.DNS.Provider != "cloudflare" {
		return oops.Code(domain.CodeValidation).Errorf("config: acme.dns.provider must be \"cloudflare\" (got %q)", acme.DNS.Provider)
	}
	if acme.DNS.Provider == "cloudflare" && acme.DNS.Cloudflare == nil {
		return oops.Code(domain.CodeValidation).Errorf("config: acme.dns.cloudflare section is required when provider is \"cloudflare\"")
	}
	if acme.DNS.Cloudflare != nil && acme.DNS.Cloudflare.APIToken == "" {
		return oops.Code(domain.CodeValidation).Errorf("config: acme.dns.cloudflare.api_token is required")
	}

	return nil
}

// validate checks all hook definitions for correctness.
func (h *HooksConfig) validate() error {
	seen := make(map[string]struct{})
	for _, hook := range h.OnSuccess {
		if err := hook.validate(); err != nil {
			return err
		}
		if _, exists := seen[hook.Name]; exists {
			return oops.Code(domain.CodeValidation).Errorf("config: duplicate hook name %q in on_success", hook.Name)
		}
		seen[hook.Name] = struct{}{}
	}

	seen = make(map[string]struct{})
	for _, hook := range h.OnFailure {
		if err := hook.validate(); err != nil {
			return err
		}
		if _, exists := seen[hook.Name]; exists {
			return oops.Code(domain.CodeValidation).Errorf("config: duplicate hook name %q in on_failure", hook.Name)
		}
		seen[hook.Name] = struct{}{}
	}

	return nil
}

// validate checks a single hook definition.
func (h *HookDefinition) validate() error {
	if h.Name == "" {
		return oops.Code(domain.CodeValidation).Errorf("config: hook name must be non-empty")
	}
	if len(h.Name) > MaxHookNameLength {
		return oops.Code(domain.CodeValidation).Errorf("config: hook name %q exceeds %d character limit", h.Name, MaxHookNameLength)
	}
	if !isValidKebabCase(h.Name) {
		return oops.Code(domain.CodeValidation).Errorf("config: hook name %q is invalid (must be kebab-case: lowercase letters, numbers, and hyphens)", h.Name)
	}
	if strings.TrimSpace(h.Command) == "" {
		return oops.Code(domain.CodeValidation).Errorf("config: hook %q has empty or whitespace-only command", h.Name)
	}
	return nil
}

// isValidKebabCase checks if s is valid kebab-case:
// lowercase alphanumeric segments separated by single hyphens, no leading/trailing hyphens.
func isValidKebabCase(s string) bool {
	if s == "" {
		return false
	}
	if s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	prevHyphen := false
	for _, c := range s {
		switch {
		case c == '-':
			if prevHyphen {
				return false
			}
			prevHyphen = true
		case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'):
			prevHyphen = false
		default:
			return false
		}
	}
	return true
}

// ExpandEnvVars replaces ${VAR} references in s with environment variable values.
// It supports ${VAR:-default} for fallback values when VAR is unset or empty.
// Use $$ to produce a literal $.
// Returns an error if a referenced variable is unset and no default is provided.
func ExpandEnvVars(s string) (string, error) {
	var b strings.Builder
	b.Grow(len(s))

	i := 0
	for i < len(s) {
		if s[i] != '$' {
			b.WriteByte(s[i])
			i++
			continue
		}

		// Escaped dollar
		if i+1 < len(s) && s[i+1] == '$' {
			b.WriteByte('$')
			i += 2
			continue
		}

		// ${VAR} or ${VAR:-default}
		if i+1 < len(s) && s[i+1] == '{' {
			end := strings.IndexByte(s[i:], '}')
			if end == -1 {
				return "", oops.Code(domain.CodeValidation).Errorf("config: unclosed ${...} in %q", s)
			}
			expr := s[i+2 : i+end]
			i += end + 1

			varName, defaultVal, hasDefault := strings.Cut(expr, ":-")
			if varName == "" {
				return "", oops.Code(domain.CodeValidation).Errorf("config: empty variable name in ${...}")
			}

			val, ok := os.LookupEnv(varName)
			if !ok || val == "" {
				if hasDefault {
					b.WriteString(defaultVal)
				} else {
					return "", oops.Code(domain.CodeValidation).Errorf("config: environment variable %q is not set", varName)
				}
			} else {
				b.WriteString(val)
			}
			continue
		}

		// Bare $ not followed by { or $ — pass through literally
		b.WriteByte(s[i])
		i++
	}

	return b.String(), nil
}

// checkConfigPermissions rejects world-writable config files on Unix.
func checkConfigPermissions(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return oops.Wrapf(err, "stat config file")
	}

	mode := info.Mode().Perm()
	// Reject group-writable (g+w = 0o020) or world-writable (o+w = 0o002).
	// Either allows untrusted parties to tamper with hook commands.
	if mode&0o022 != 0 {
		return oops.Code(domain.CodeValidation).Errorf(
			"config: file %q has unsafe permissions (mode %04o); "+
				"group-write and world-write must be removed as the config contains hook commands; "+
				"fix with: chmod go-w %s",
			path, mode, path,
		)
	}

	return nil
}
