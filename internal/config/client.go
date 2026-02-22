package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/BurntSushi/toml"
)

// ClientConfig holds the client connection settings.
type ClientConfig struct {
	ServerAddress string `toml:"server_address"`
	CertPath      string `toml:"cert_path"`
	KeyPath       string `toml:"key_path"`
	CACertPath    string `toml:"ca_cert_path"`
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
	cfg.CertPath = expandTilde(cfg.CertPath)
	cfg.KeyPath = expandTilde(cfg.KeyPath)
	cfg.CACertPath = expandTilde(cfg.CACertPath)

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// validate checks that all required fields are set.
func (c *ClientConfig) validate() error {
	if c.ServerAddress == "" {
		return fmt.Errorf("client config: server_address is required")
	}
	return nil
}

// loadClientConfigFile reads a client config TOML file.
func loadClientConfigFile(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read client config: %w", err)
	}

	var cfg ClientConfig
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse client config: %w", err)
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
	return "", fmt.Errorf("no client config file found")
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

	// 2. ~/.config fallback
	if home, err := os.UserHomeDir(); err == nil {
		for _, name := range filenames {
			paths = append(paths, filepath.Join(home, ".config", "router-hosts", name))
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
		cfg.ServerAddress = v
	}
	if v := os.Getenv(EnvCert); v != "" {
		cfg.CertPath = v
	}
	if v := os.Getenv(EnvKey); v != "" {
		cfg.KeyPath = v
	}
	if v := os.Getenv(EnvCA); v != "" {
		cfg.CACertPath = v
	}
}

// applyClientOverrides applies CLI arg overrides to config fields.
func applyClientOverrides(cfg *ClientConfig, o *ClientConfigOverrides) {
	if o.ServerAddress != nil {
		cfg.ServerAddress = *o.ServerAddress
	}
	if o.CertPath != nil {
		cfg.CertPath = *o.CertPath
	}
	if o.KeyPath != nil {
		cfg.KeyPath = *o.KeyPath
	}
	if o.CACertPath != nil {
		cfg.CACertPath = *o.CACertPath
	}
}

// expandTilde replaces a leading ~ with the user's home directory.
func expandTilde(path string) string {
	if !strings.HasPrefix(path, "~") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, path[1:])
}
