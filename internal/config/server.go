// Package config provides configuration loading for the router-hosts server
// and client. Server config is loaded from TOML files with the same structure
// as the Rust implementation for compatibility.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/BurntSushi/toml"
)

// Default values for retention policy.
const (
	DefaultMaxSnapshots = 50
	DefaultMaxAgeDays   = 30

	// DefaultExportIntervalSecs is the default OTEL metrics export interval.
	DefaultExportIntervalSecs = 60

	// MaxHookNameLength is the maximum allowed length for hook names.
	MaxHookNameLength = 50
)

// Config is the top-level server configuration, loaded from TOML.
type Config struct {
	Server    ServerConfig     `toml:"server"`
	Database  DatabaseConfig   `toml:"database"`
	TLS       TLSConfig        `toml:"tls"`
	Retention RetentionConfig  `toml:"retention"`
	Hooks     HooksConfig      `toml:"hooks"`
	Metrics   *MetricsConfig   `toml:"metrics,omitempty"`
}

// ServerConfig holds the core server settings.
type ServerConfig struct {
	BindAddress   string `toml:"bind_address"`
	HostsFilePath string `toml:"hosts_file_path"`
}

// DatabaseConfig holds the database connection settings.
// For Go, we only support SQLite, so this is simplified to a path.
type DatabaseConfig struct {
	Path string `toml:"path"`
}

// TLSConfig holds paths to TLS certificates for mTLS.
type TLSConfig struct {
	CertPath   string `toml:"cert_path"`
	KeyPath    string `toml:"key_path"`
	CACertPath string `toml:"ca_cert_path"`
}

// RetentionConfig controls snapshot retention policy.
type RetentionConfig struct {
	MaxSnapshots int `toml:"max_snapshots"`
	MaxAgeDays   int `toml:"max_age_days"`
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
			return "", fmt.Errorf("determine home directory: %w", err)
		}
		dataDir = filepath.Join(home, "Library", "Application Support")
	default: // linux and others use XDG
		if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
			dataDir = xdg
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", fmt.Errorf("determine home directory: %w", err)
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
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}

	// Apply defaults for retention if zero-valued
	if cfg.Retention.MaxSnapshots == 0 {
		cfg.Retention.MaxSnapshots = DefaultMaxSnapshots
	}
	if cfg.Retention.MaxAgeDays == 0 {
		cfg.Retention.MaxAgeDays = DefaultMaxAgeDays
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
		return fmt.Errorf("config: bind_address is required")
	}
	if c.Server.HostsFilePath == "" {
		return fmt.Errorf("config: hosts_file_path is required")
	}

	if err := c.Hooks.validate(); err != nil {
		return err
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
			return fmt.Errorf("config: duplicate hook name %q in on_success", hook.Name)
		}
		seen[hook.Name] = struct{}{}
	}

	seen = make(map[string]struct{})
	for _, hook := range h.OnFailure {
		if err := hook.validate(); err != nil {
			return err
		}
		if _, exists := seen[hook.Name]; exists {
			return fmt.Errorf("config: duplicate hook name %q in on_failure", hook.Name)
		}
		seen[hook.Name] = struct{}{}
	}

	return nil
}

// validate checks a single hook definition.
func (h *HookDefinition) validate() error {
	if h.Name == "" {
		return fmt.Errorf("config: hook name must be non-empty")
	}
	if len(h.Name) > MaxHookNameLength {
		return fmt.Errorf("config: hook name %q exceeds %d character limit", h.Name, MaxHookNameLength)
	}
	if !isValidKebabCase(h.Name) {
		return fmt.Errorf("config: hook name %q is invalid (must be kebab-case: lowercase letters, numbers, and hyphens)", h.Name)
	}
	if strings.TrimSpace(h.Command) == "" {
		return fmt.Errorf("config: hook %q has empty or whitespace-only command", h.Name)
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

// checkConfigPermissions rejects world-writable config files on Unix.
func checkConfigPermissions(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat config file: %w", err)
	}

	mode := info.Mode().Perm()
	// Reject world-writable (o+w = 0o002)
	if mode&0o002 != 0 {
		return fmt.Errorf(
			"config: file %q is world-writable (mode %04o); "+
				"this is a security risk as the config contains hook commands; "+
				"fix with: chmod o-w %s",
			path, mode, path,
		)
	}

	// Warn about group-writable but don't fail
	if mode&0o020 != 0 {
		slog.Warn("config file is group-writable, consider restricting",
			"path", path,
			"mode", fmt.Sprintf("%04o", mode),
		)
	}

	return nil
}
