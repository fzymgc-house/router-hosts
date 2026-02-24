package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/samber/oops"

	"github.com/fzymgc-house/router-hosts/internal/domain"
)

// ClientConfig holds the client connection settings.
type ClientConfig struct {
	Server ClientServerConfig `toml:"server"`
	TLS    ClientTLSConfig    `toml:"tls"`
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
	ServerAddress *string
	CertPath      *string
	KeyPath       *string
	CACertPath    *string
}

// Client env var names.
const (
	EnvServer = "ROUTER_HOSTS_SERVER"
	EnvCert   = "ROUTER_HOSTS_CERT"
	EnvKey    = "ROUTER_HOSTS_KEY"
	EnvCA     = "ROUTER_HOSTS_CA"
)

// LoadClientConfig loads client configuration with precedence:
// CLI args > environment variables > config file.
func LoadClientConfig(overrides *ClientConfigOverrides) (*ClientConfig, error) {
	cfg := &ClientConfig{}

	// Layer 1: config file (lowest priority)
	if path, err := findClientConfigFile(); err == nil {
		if fileCfg, err := loadClientConfigFile(path); err == nil {
			*cfg = *fileCfg
		}
	}

	// Layer 2: environment variables
	applyClientEnv(cfg)

	// Layer 3: CLI overrides (highest priority)
	if overrides != nil {
		applyClientOverrides(cfg, overrides)
	}

	// Expand tildes in paths
	cfg.TLS.CertPath = expandTilde(cfg.TLS.CertPath)
	cfg.TLS.KeyPath = expandTilde(cfg.TLS.KeyPath)
	cfg.TLS.CACertPath = expandTilde(cfg.TLS.CACertPath)

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

// applyClientEnv overrides config fields with environment variable values when set.
func applyClientEnv(cfg *ClientConfig) {
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
