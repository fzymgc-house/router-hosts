package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const clientConfigContent = `
[server]
address = "localhost:50051"

[tls]
cert_path = "/etc/router-hosts/client.crt"
key_path = "/etc/router-hosts/client.key"
ca_cert_path = "/etc/router-hosts/ca.crt"
`

func writeClientConfig(t *testing.T, dir, content string) string {
	t.Helper()
	cfgDir := filepath.Join(dir, "router-hosts")
	require.NoError(t, os.MkdirAll(cfgDir, 0o700))
	path := filepath.Join(cfgDir, "client.toml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestLoadClientConfig_FromFile(t *testing.T) {
	dir := t.TempDir()
	writeClientConfig(t, dir, clientConfigContent)

	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("ROUTER_HOSTS_SERVER", "")
	t.Setenv("ROUTER_HOSTS_CERT", "")
	t.Setenv("ROUTER_HOSTS_KEY", "")
	t.Setenv("ROUTER_HOSTS_CA", "")

	cfg, err := LoadClientConfig(nil)
	require.NoError(t, err)

	assert.Equal(t, "localhost:50051", cfg.Server.Address)
	assert.Equal(t, "/etc/router-hosts/client.crt", cfg.TLS.CertPath)
	assert.Equal(t, "/etc/router-hosts/client.key", cfg.TLS.KeyPath)
	assert.Equal(t, "/etc/router-hosts/ca.crt", cfg.TLS.CACertPath)
}

func TestLoadClientConfig_EnvOverridesFile(t *testing.T) {
	dir := t.TempDir()
	writeClientConfig(t, dir, clientConfigContent)

	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("ROUTER_HOSTS_SERVER", "env-server:9090")
	t.Setenv("ROUTER_HOSTS_CERT", "/env/cert.pem")
	t.Setenv("ROUTER_HOSTS_KEY", "/env/key.pem")
	t.Setenv("ROUTER_HOSTS_CA", "/env/ca.pem")

	cfg, err := LoadClientConfig(nil)
	require.NoError(t, err)

	assert.Equal(t, "env-server:9090", cfg.Server.Address)
	assert.Equal(t, "/env/cert.pem", cfg.TLS.CertPath)
	assert.Equal(t, "/env/key.pem", cfg.TLS.KeyPath)
	assert.Equal(t, "/env/ca.pem", cfg.TLS.CACertPath)
}

func TestLoadClientConfig_CLIOverridesEnv(t *testing.T) {
	t.Setenv("ROUTER_HOSTS_SERVER", "env-server:9090")
	t.Setenv("ROUTER_HOSTS_CERT", "/env/cert.pem")
	t.Setenv("ROUTER_HOSTS_KEY", "")
	t.Setenv("ROUTER_HOSTS_CA", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir()) // empty dir, no file

	cliServer := "cli-server:8080"
	cliCert := "/cli/cert.pem"
	cfg, err := LoadClientConfig(&ClientConfigOverrides{
		ServerAddress: &cliServer,
		CertPath:      &cliCert,
	})
	require.NoError(t, err)

	assert.Equal(t, "cli-server:8080", cfg.Server.Address)
	assert.Equal(t, "/cli/cert.pem", cfg.TLS.CertPath)
}

func TestLoadClientConfig_MissingServerAddress(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("ROUTER_HOSTS_SERVER", "")
	t.Setenv("ROUTER_HOSTS_CERT", "")
	t.Setenv("ROUTER_HOSTS_KEY", "")
	t.Setenv("ROUTER_HOSTS_CA", "")

	_, err := LoadClientConfig(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server address is required")
}

func TestLoadClientConfig_TildeExpansion(t *testing.T) {
	t.Setenv("ROUTER_HOSTS_SERVER", "localhost:50051")
	t.Setenv("ROUTER_HOSTS_CERT", "~/certs/client.crt")
	t.Setenv("ROUTER_HOSTS_KEY", "~/certs/client.key")
	t.Setenv("ROUTER_HOSTS_CA", "~/certs/ca.crt")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	cfg, err := LoadClientConfig(nil)
	require.NoError(t, err)

	home, err := os.UserHomeDir()
	require.NoError(t, err)

	assert.Equal(t, filepath.Join(home, "certs/client.crt"), cfg.TLS.CertPath)
	assert.Equal(t, filepath.Join(home, "certs/client.key"), cfg.TLS.KeyPath)
	assert.Equal(t, filepath.Join(home, "certs/ca.crt"), cfg.TLS.CACertPath)
}

func TestLoadClientConfig_NoTildeNoExpansion(t *testing.T) {
	t.Setenv("ROUTER_HOSTS_SERVER", "localhost:50051")
	t.Setenv("ROUTER_HOSTS_CERT", "/absolute/cert.crt")
	t.Setenv("ROUTER_HOSTS_KEY", "")
	t.Setenv("ROUTER_HOSTS_CA", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	cfg, err := LoadClientConfig(nil)
	require.NoError(t, err)

	assert.Equal(t, "/absolute/cert.crt", cfg.TLS.CertPath)
}

func TestClientConfigSearchPaths_XDGFirst(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/custom/xdg")

	paths := clientConfigSearchPaths()
	require.NotEmpty(t, paths)
	assert.Equal(t, "/custom/xdg/router-hosts/client.toml", paths[0])
	assert.Equal(t, "/custom/xdg/router-hosts/config.toml", paths[1])
}

func TestClientConfigSearchPaths_FallbackToHomeConfig(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")

	paths := clientConfigSearchPaths()
	require.NotEmpty(t, paths)

	home, err := os.UserHomeDir()
	require.NoError(t, err)

	assert.Equal(t, filepath.Join(home, ".config", "router-hosts", "client.toml"), paths[0])
	assert.Equal(t, filepath.Join(home, ".config", "router-hosts", "config.toml"), paths[1])
}

func TestFindClientConfigFile_PrefersClientTomlOverConfigToml(t *testing.T) {
	dir := t.TempDir()
	cfgDir := filepath.Join(dir, "router-hosts")
	require.NoError(t, os.MkdirAll(cfgDir, 0o700))

	// Create both client.toml and config.toml
	require.NoError(t, os.WriteFile(filepath.Join(cfgDir, "client.toml"), []byte("[server]\naddress = \"from-client\"\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(cfgDir, "config.toml"), []byte("[server]\naddress = \"from-config\"\n"), 0o600))

	t.Setenv("XDG_CONFIG_HOME", dir)
	path, err := findClientConfigFile()
	require.NoError(t, err)
	assert.Contains(t, path, "client.toml")
}

func TestFindClientConfigFile_FallsBackToConfigToml(t *testing.T) {
	dir := t.TempDir()
	cfgDir := filepath.Join(dir, "router-hosts")
	require.NoError(t, os.MkdirAll(cfgDir, 0o700))

	// Only config.toml exists (no client.toml)
	require.NoError(t, os.WriteFile(filepath.Join(cfgDir, "config.toml"), []byte(clientConfigContent), 0o600))

	t.Setenv("XDG_CONFIG_HOME", dir)
	path, err := findClientConfigFile()
	require.NoError(t, err)
	assert.Contains(t, path, "config.toml")
}

func TestFindClientConfigFile_XDGPriority(t *testing.T) {
	// Create both XDG and ~/.config entries
	xdgDir := t.TempDir()
	homeDir := t.TempDir()

	writeClientConfig(t, xdgDir, "[server]\naddress = \"xdg-server\"\n")
	writeClientConfig(t, filepath.Join(homeDir, ".config"), "[server]\naddress = \"home-server\"\n")

	t.Setenv("XDG_CONFIG_HOME", xdgDir)
	// We can't override UserHomeDir, but XDG should be checked first
	path, err := findClientConfigFile()
	require.NoError(t, err)
	assert.Contains(t, path, xdgDir)
}

func TestLoadClientConfigFile_ValidTOML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.toml")
	require.NoError(t, os.WriteFile(path, []byte(clientConfigContent), 0o600))

	cfg, err := loadClientConfigFile(path)
	require.NoError(t, err)
	assert.Equal(t, "localhost:50051", cfg.Server.Address)
}

func TestLoadClientConfigFile_InvalidTOML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.toml")
	require.NoError(t, os.WriteFile(path, []byte("{{invalid"), 0o600))

	_, err := loadClientConfigFile(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse client config")
}

func TestLoadClientConfigFile_Missing(t *testing.T) {
	_, err := loadClientConfigFile("/nonexistent/client.toml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read client config")
}

func TestExpandTilde(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "with tilde", path: "~/foo/bar", want: filepath.Join(home, "foo/bar")},
		{name: "absolute", path: "/foo/bar", want: "/foo/bar"},
		{name: "empty", path: "", want: ""},
		{name: "tilde only", path: "~", want: home},
		{name: "tilde slash", path: "~/", want: home},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, expandTilde(tt.path))
		})
	}
}

func TestApplyClientEnv(t *testing.T) {
	t.Setenv("ROUTER_HOSTS_SERVER", "env-server")
	t.Setenv("ROUTER_HOSTS_CERT", "/env/cert")
	t.Setenv("ROUTER_HOSTS_KEY", "/env/key")
	t.Setenv("ROUTER_HOSTS_CA", "/env/ca")

	cfg := &ClientConfig{
		Server: ClientServerConfig{Address: "file-server"},
	}
	require.NoError(t, applyClientEnv(cfg))

	assert.Equal(t, "env-server", cfg.Server.Address)
	assert.Equal(t, "/env/cert", cfg.TLS.CertPath)
	assert.Equal(t, "/env/key", cfg.TLS.KeyPath)
	assert.Equal(t, "/env/ca", cfg.TLS.CACertPath)
}

// ---------------------------------------------------------------------------
// Invalid client config file must be a startup error, not a silent fallback
// (review round-2 H3; internal/config/client.go:55-59 used to shadow and
// discard both inner errors).
// ---------------------------------------------------------------------------

func TestLoadClientConfig_NoFileIsNotAnError(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir()) // empty dir, no file on any search path
	t.Setenv("ROUTER_HOSTS_SERVER", "env-only:50051")
	t.Setenv("ROUTER_HOSTS_CERT", "")
	t.Setenv("ROUTER_HOSTS_KEY", "")
	t.Setenv("ROUTER_HOSTS_CA", "")

	cfg, err := LoadClientConfig(nil)
	require.NoError(t, err)
	assert.Equal(t, "env-only:50051", cfg.Server.Address)
}

func TestLoadClientConfig_MalformedFileErrors(t *testing.T) {
	dir := t.TempDir()
	path := writeClientConfig(t, dir, "{{invalid")
	t.Setenv("XDG_CONFIG_HOME", dir)

	_, err := LoadClientConfig(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), path)
	assert.Contains(t, err.Error(), "parse client config")
}

func TestLoadClientConfig_UnknownKeyErrors(t *testing.T) {
	dir := t.TempDir()
	writeClientConfig(t, dir, "[server]\naddress = \"localhost:50051\"\nbogus_key = \"x\"\n")
	t.Setenv("XDG_CONFIG_HOME", dir)

	_, err := LoadClientConfig(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bogus_key")
}

func TestLoadClientConfig_UnreadableFileErrors(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root can read files regardless of mode")
	}
	dir := t.TempDir()
	path := writeClientConfig(t, dir, clientConfigContent)
	require.NoError(t, os.Chmod(path, 0o000))
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	t.Setenv("XDG_CONFIG_HOME", dir)

	_, err := LoadClientConfig(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read client config")
}

// ---------------------------------------------------------------------------
// Explicit --config path resolution (gap G-01-1). An explicit path must be
// loaded directly and must win over the XDG search, which must not run at
// all when a path is supplied.
// ---------------------------------------------------------------------------

func TestLoadClientConfig_ExplicitPathBeatsXDG(t *testing.T) {
	xdgDir := t.TempDir()
	writeClientConfig(t, xdgDir, "[server]\naddress = \"decoy.invalid:59999\"\n")
	t.Setenv("XDG_CONFIG_HOME", xdgDir)
	t.Setenv("ROUTER_HOSTS_SERVER", "")
	t.Setenv("ROUTER_HOSTS_CERT", "")
	t.Setenv("ROUTER_HOSTS_KEY", "")
	t.Setenv("ROUTER_HOSTS_CA", "")

	explicitDir := t.TempDir()
	explicitPath := filepath.Join(explicitDir, "explicit.toml")
	require.NoError(t, os.WriteFile(explicitPath, []byte("[server]\naddress = \"explicit.example:18443\"\n"), 0o600))

	cfg, err := LoadClientConfig(&ClientConfigOverrides{ConfigPath: &explicitPath})
	require.NoError(t, err)
	assert.Equal(t, "explicit.example:18443", cfg.Server.Address)
}

func TestLoadClientConfig_EnvDoesNotMaskFileError(t *testing.T) {
	dir := t.TempDir()
	writeClientConfig(t, dir, "{{invalid")
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("ROUTER_HOSTS_SERVER", "env-server:9090")

	_, err := LoadClientConfig(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse client config")
}

// ---------------------------------------------------------------------------
// Stream collection limits (D-14, TMPL-07, review L1/L6).
// ---------------------------------------------------------------------------

func TestLoadClientConfig_LimitsFromFile(t *testing.T) {
	dir := t.TempDir()
	writeClientConfig(t, dir, `
[server]
address = "localhost:50051"

[limits]
max_stream_entries = 10
`)
	t.Setenv("XDG_CONFIG_HOME", dir)

	cfg, err := LoadClientConfig(nil)
	require.NoError(t, err)
	assert.Equal(t, 10, cfg.Limits.MaxStreamEntries)
}

func TestLoadClientConfig_LimitsBytesFromFile(t *testing.T) {
	dir := t.TempDir()
	writeClientConfig(t, dir, `
[server]
address = "localhost:50051"

[limits]
max_stream_bytes = 4096
`)
	t.Setenv("XDG_CONFIG_HOME", dir)

	cfg, err := LoadClientConfig(nil)
	require.NoError(t, err)
	assert.Equal(t, int64(4096), cfg.Limits.MaxStreamBytes)
}

func TestLoadClientConfig_LimitsDefault(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("ROUTER_HOSTS_SERVER", "localhost:50051")

	cfg, err := LoadClientConfig(nil)
	require.NoError(t, err)
	assert.Equal(t, DefaultMaxStreamEntries, cfg.Limits.MaxStreamEntries)
	assert.Equal(t, int64(DefaultMaxStreamBytes), cfg.Limits.MaxStreamBytes)
}

func TestLoadClientConfig_LimitsFromEnv(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("ROUTER_HOSTS_SERVER", "localhost:50051")
	t.Setenv("ROUTER_HOSTS_MAX_STREAM_ENTRIES", "25")
	t.Setenv("ROUTER_HOSTS_MAX_STREAM_BYTES", "4096")

	cfg, err := LoadClientConfig(nil)
	require.NoError(t, err)
	assert.Equal(t, 25, cfg.Limits.MaxStreamEntries)
	assert.Equal(t, int64(4096), cfg.Limits.MaxStreamBytes)
}

func TestLoadClientConfig_LimitsInvalid(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("ROUTER_HOSTS_SERVER", "localhost:50051")
	t.Setenv("ROUTER_HOSTS_MAX_STREAM_ENTRIES", "not-a-number")

	_, err := LoadClientConfig(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ROUTER_HOSTS_MAX_STREAM_ENTRIES")
}

func TestLoadClientConfig_LimitsBytesInvalid(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("ROUTER_HOSTS_SERVER", "localhost:50051")
	t.Setenv("ROUTER_HOSTS_MAX_STREAM_BYTES", "not-a-number")

	_, err := LoadClientConfig(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ROUTER_HOSTS_MAX_STREAM_BYTES")
}

func TestApplyClientOverrides(t *testing.T) {
	server := "override-server"
	cert := "/override/cert"

	cfg := &ClientConfig{
		Server: ClientServerConfig{Address: "original"},
		TLS:    ClientTLSConfig{CertPath: "/original/cert", KeyPath: "/original/key"},
	}

	applyClientOverrides(cfg, &ClientConfigOverrides{
		ServerAddress: &server,
		CertPath:      &cert,
	})

	assert.Equal(t, "override-server", cfg.Server.Address)
	assert.Equal(t, "/override/cert", cfg.TLS.CertPath)
	assert.Equal(t, "/original/key", cfg.TLS.KeyPath) // unchanged
}
