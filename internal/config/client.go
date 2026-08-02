package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/samber/oops"

	"github.com/fzymgc-house/router-hosts/internal/domain"
)

// Default values for client-side stream collection bounds (D-14, TMPL-07).
const (
	// DefaultMaxStreamEntries bounds the number of entries a single
	// collecting call site (host list, host search, snapshot list, render)
	// accumulates before refusing the whole response. It is an entry count
	// rather than a byte budget because Data.Count is a first-class
	// template-contract field (D-03): the client already needs the full
	// entry count to render, so an entry ceiling is a natural first bound.
	// A deployment with a larger inventory raises it through the
	// [limits] config table or ROUTER_HOSTS_MAX_STREAM_ENTRIES rather than
	// being blocked by a compiled-in ceiling — D-14 rejected a fixed
	// constant for exactly that reason.
	DefaultMaxStreamEntries = 50_000

	// DefaultMaxStreamBytes bounds the total serialized size of every
	// message a single collecting call site accumulates, independent of
	// DefaultMaxStreamEntries. An entry count alone does not bound memory:
	// hostnames are capped at 253 bytes and aliases at 50
	// (internal/validation/validation.go:32,:82), but comment and tag text
	// carry no equivalent limit, so a hostile or buggy server can exhaust a
	// client with far fewer than 50,000 entries by making each one
	// enormous (review L1). The two bounds are independent; either one
	// refuses. This budget counts serialized protobuf bytes as reported by
	// proto.Size on the received message — exactly what crossed the wire —
	// and is a conservative operational bound on wire volume received, NOT
	// an exact Go heap ceiling: slice headers, string headers, and the
	// converted domain objects all sit outside it (review M7).
	DefaultMaxStreamBytes = 64 << 20 // 64 MiB
)

// ClientLimitsConfig holds client-side stream collection bounds (D-14,
// TMPL-07). Both bounds are enforced independently at every collecting call
// site: a stream can trip the byte budget while under the entry cap, and the
// reverse.
type ClientLimitsConfig struct {
	MaxStreamEntries int   `toml:"max_stream_entries"`
	MaxStreamBytes   int64 `toml:"max_stream_bytes"`
}

// ClientConfig holds the client connection settings.
type ClientConfig struct {
	Server ClientServerConfig `toml:"server"`
	TLS    ClientTLSConfig    `toml:"tls"`
	Limits ClientLimitsConfig `toml:"limits"`
}

// ClientServerConfig holds the server connection settings.
type ClientServerConfig struct {
	Address string `toml:"address"`
}

// ClientTLSConfig holds the client TLS certificate paths.
type ClientTLSConfig struct {
	CertPath   string `toml:"cert_path"`
	KeyPath    string `toml:"key_path"`
	CACertPath string `toml:"ca_cert_path"`
}

// ClientConfigOverrides holds optional CLI arg overrides.
// Non-nil fields override env vars and config file values.
type ClientConfigOverrides struct {
	ServerAddress    *string
	CertPath         *string
	KeyPath          *string
	CACertPath       *string
	MaxStreamEntries *int
	MaxStreamBytes   *int64

	// ConfigPath is not like the fields above: it does not override a
	// resolved value, it selects which file the lowest (layer 1) resolution
	// layer reads. Nil or empty means today's XDG auto-discovery via
	// findClientConfigFile. Non-nil and non-empty means LoadClientConfig
	// reads exactly that file and does not consult the XDG search at all.
	ConfigPath *string
}

// Client env var names.
const (
	EnvServer = "ROUTER_HOSTS_SERVER"
	EnvCert   = "ROUTER_HOSTS_CERT"
	EnvKey    = "ROUTER_HOSTS_KEY"
	EnvCA     = "ROUTER_HOSTS_CA"

	// EnvMaxStreamEntries and EnvMaxStreamBytes override the [limits]
	// stream-collection bounds (D-14, TMPL-07).
	EnvMaxStreamEntries = "ROUTER_HOSTS_MAX_STREAM_ENTRIES"
	EnvMaxStreamBytes   = "ROUTER_HOSTS_MAX_STREAM_BYTES"
)

// LoadClientConfig loads client configuration with precedence:
// CLI args > environment variables > config file.
func LoadClientConfig(overrides *ClientConfigOverrides) (*ClientConfig, error) {
	cfg := &ClientConfig{}

	// Layer 1: config file (lowest priority).
	//
	// findClientConfigFile's error is benign: no config file on any search
	// path is a fully supported deployment (env vars and flags alone), so we
	// skip the file layer and continue. Once a path is found, however,
	// loadClientConfigFile's error is NOT benign and must reach the caller —
	// a config file that exists but cannot be parsed, carries an unknown key,
	// or otherwise fails to load is an operator error, not an absent file,
	// and silently falling back to defaults would make loadClientConfigFile's
	// strict meta.Undecoded() unknown-key rejection unreachable.
	//
	// An explicit path (overrides.ConfigPath) replaces this whole layer: it
	// is loaded directly, the XDG search is never consulted, and a failure
	// to load it is never a benign "no file found" — it is an operator
	// error naming the exact path that was supplied (G-01-1). This must
	// stay in layer 1: handling it inside applyClientOverrides (layer 3,
	// after env) would silently promote an explicit file above environment
	// variables and invert the documented precedence.
	if overrides != nil && overrides.ConfigPath != nil && *overrides.ConfigPath != "" {
		path := expandTilde(*overrides.ConfigPath)
		fileCfg, loadErr := loadClientConfigFile(path)
		if loadErr != nil {
			return nil, oops.Wrapf(loadErr, "loading client config %s", path)
		}
		*cfg = *fileCfg
	} else if path, findErr := findClientConfigFile(); findErr == nil {
		fileCfg, loadErr := loadClientConfigFile(path)
		if loadErr != nil {
			return nil, oops.Wrapf(loadErr, "loading client config %s", path)
		}
		*cfg = *fileCfg
	}

	// Layer 2: environment variables
	if err := applyClientEnv(cfg); err != nil {
		return nil, err
	}

	// Layer 3: CLI overrides (highest priority)
	if overrides != nil {
		applyClientOverrides(cfg, overrides)
	}

	// Expand tildes in paths
	cfg.TLS.CertPath = expandTilde(cfg.TLS.CertPath)
	cfg.TLS.KeyPath = expandTilde(cfg.TLS.KeyPath)
	cfg.TLS.CACertPath = expandTilde(cfg.TLS.CACertPath)

	// Substitute safe defaults for the stream collection bounds when
	// nothing (file, env, or override) set them, so a zero configured value
	// resolves to the protective default rather than to "unlimited"
	// (T-1-09). This runs after every layer and before validate.
	if cfg.Limits.MaxStreamEntries == 0 {
		cfg.Limits.MaxStreamEntries = DefaultMaxStreamEntries
	}
	if cfg.Limits.MaxStreamBytes == 0 {
		cfg.Limits.MaxStreamBytes = DefaultMaxStreamBytes
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// validate checks that all required fields are set.
func (c *ClientConfig) validate() error {
	if c.Server.Address == "" {
		return oops.Code(domain.CodeValidation).Errorf("client config: server address is required")
	}
	if c.Limits.MaxStreamEntries < 0 {
		return oops.Code(domain.CodeValidation).Errorf(
			"client config: limits.max_stream_entries must not be negative (got %d)", c.Limits.MaxStreamEntries)
	}
	if c.Limits.MaxStreamBytes < 0 {
		return oops.Code(domain.CodeValidation).Errorf(
			"client config: limits.max_stream_bytes must not be negative (got %d)", c.Limits.MaxStreamBytes)
	}
	return nil
}

// loadClientConfigFile reads a client config TOML file.
func loadClientConfigFile(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, oops.Wrapf(err, "read client config")
	}

	var cfg ClientConfig
	meta, err := toml.Decode(string(data), &cfg)
	if err != nil {
		return nil, oops.Wrapf(err, "parse client config")
	}
	if keys := meta.Undecoded(); len(keys) > 0 {
		strs := make([]string, len(keys))
		for i, k := range keys {
			strs[i] = k.String()
		}
		return nil, oops.Code(domain.CodeValidation).Errorf("client config: unknown keys: [%s]", strings.Join(strs, ", "))
	}
	return &cfg, nil
}

// findClientConfigFile searches XDG/platform config directories for client.toml.
// Search order:
//  1. $XDG_CONFIG_HOME/router-hosts/client.toml
//  2. ~/.config/router-hosts/client.toml (fallback)
//  3. Platform config dir (macOS: ~/Library/Application Support)
func findClientConfigFile() (string, error) {
	candidates := clientConfigSearchPaths()
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	return "", oops.Errorf("no client config file found")
}

// clientConfigSearchPaths returns the ordered list of paths to search.
// Within each directory, client.toml is preferred over config.toml.
func clientConfigSearchPaths() []string {
	filenames := []string{"client.toml", "config.toml"}
	var paths []string

	// 1. XDG_CONFIG_HOME
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		for _, name := range filenames {
			paths = append(paths, filepath.Join(xdg, "router-hosts", name))
		}
	}

	// 2. ~/.config fallback (only when XDG_CONFIG_HOME is not set)
	if os.Getenv("XDG_CONFIG_HOME") == "" {
		if home, err := os.UserHomeDir(); err == nil {
			for _, name := range filenames {
				paths = append(paths, filepath.Join(home, ".config", "router-hosts", name))
			}
		}
	}

	// 3. Platform config dir (macOS only — separate from ~/.config)
	if runtime.GOOS == "darwin" {
		if home, err := os.UserHomeDir(); err == nil {
			for _, name := range filenames {
				paths = append(paths, filepath.Join(home, "Library", "Application Support", "router-hosts", name))
			}
		}
	}

	return paths
}

// applyClientEnv overrides config fields with environment variable values
// when set. A malformed (non-numeric) EnvMaxStreamEntries/EnvMaxStreamBytes
// value returns an error immediately rather than being silently ignored or
// left to fall back to a default that would mask the operator's mistake.
func applyClientEnv(cfg *ClientConfig) error {
	if v := os.Getenv(EnvServer); v != "" {
		cfg.Server.Address = v
	}
	if v := os.Getenv(EnvCert); v != "" {
		cfg.TLS.CertPath = v
	}
	if v := os.Getenv(EnvKey); v != "" {
		cfg.TLS.KeyPath = v
	}
	if v := os.Getenv(EnvCA); v != "" {
		cfg.TLS.CACertPath = v
	}
	if v := os.Getenv(EnvMaxStreamEntries); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return oops.Code(domain.CodeValidation).Wrapf(
				err, "client config: %s must be a valid integer (got %q)", EnvMaxStreamEntries, v)
		}
		cfg.Limits.MaxStreamEntries = n
	}
	if v := os.Getenv(EnvMaxStreamBytes); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return oops.Code(domain.CodeValidation).Wrapf(
				err, "client config: %s must be a valid integer (got %q)", EnvMaxStreamBytes, v)
		}
		cfg.Limits.MaxStreamBytes = n
	}
	return nil
}

// applyClientOverrides applies CLI arg overrides to config fields.
func applyClientOverrides(cfg *ClientConfig, o *ClientConfigOverrides) {
	if o.ServerAddress != nil {
		cfg.Server.Address = *o.ServerAddress
	}
	if o.CertPath != nil {
		cfg.TLS.CertPath = *o.CertPath
	}
	if o.KeyPath != nil {
		cfg.TLS.KeyPath = *o.KeyPath
	}
	if o.CACertPath != nil {
		cfg.TLS.CACertPath = *o.CACertPath
	}
	if o.MaxStreamEntries != nil {
		cfg.Limits.MaxStreamEntries = *o.MaxStreamEntries
	}
	if o.MaxStreamBytes != nil {
		cfg.Limits.MaxStreamBytes = *o.MaxStreamBytes
	}
}

// expandTilde replaces a leading ~/ with the user's home directory.
// Does not handle ~user syntax — only ~/path and bare ~.
func expandTilde(path string) string {
	if path == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return home
	}
	if !strings.HasPrefix(path, "~/") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, path[2:])
}
