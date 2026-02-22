package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const clientConfigContent = `
server_address = "localhost:50051"
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

	assert.Equal(t, "localhost:50051", cfg.ServerAddress)
	assert.Equal(t, "/etc/router-hosts/client.crt", cfg.CertPath)
	assert.Equal(t, "/etc/router-hosts/client.key", cfg.KeyPath)
	assert.Equal(t, "/etc/router-hosts/ca.crt", cfg.CACertPath)
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

	assert.Equal(t, "env-server:9090", cfg.ServerAddress)
	assert.Equal(t, "/env/cert.pem", cfg.CertPath)
	assert.Equal(t, "/env/key.pem", cfg.KeyPath)
	assert.Equal(t, "/env/ca.pem", cfg.CACertPath)
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

	assert.Equal(t, "cli-server:8080", cfg.ServerAddress)
	assert.Equal(t, "/cli/cert.pem", cfg.CertPath)
}

func TestLoadClientConfig_MissingServerAddress(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("ROUTER_HOSTS_SERVER", "")
	t.Setenv("ROUTER_HOSTS_CERT", "")
	t.Setenv("ROUTER_HOSTS_KEY", "")
	t.Setenv("ROUTER_HOSTS_CA", "")

	_, err := LoadClientConfig(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server_address is required")
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

	assert.Equal(t, filepath.Join(home, "certs/client.crt"), cfg.CertPath)
	assert.Equal(t, filepath.Join(home, "certs/client.key"), cfg.KeyPath)
	assert.Equal(t, filepath.Join(home, "certs/ca.crt"), cfg.CACertPath)
}

func TestLoadClientConfig_NoTildeNoExpansion(t *testing.T) {
	t.Setenv("ROUTER_HOSTS_SERVER", "localhost:50051")
	t.Setenv("ROUTER_HOSTS_CERT", "/absolute/cert.crt")
	t.Setenv("ROUTER_HOSTS_KEY", "")
	t.Setenv("ROUTER_HOSTS_CA", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	cfg, err := LoadClientConfig(nil)
	require.NoError(t, err)

	assert.Equal(t, "/absolute/cert.crt", cfg.CertPath)
}

func TestClientConfigSearchPaths_XDGFirst(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/custom/xdg")

	paths := clientConfigSearchPaths()
	require.NotEmpty(t, paths)
	assert.Equal(t, "/custom/xdg/router-hosts/client.toml", paths[0])
}

func TestClientConfigSearchPaths_FallbackToHomeConfig(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")

	paths := clientConfigSearchPaths()
	require.NotEmpty(t, paths)

	home, err := os.UserHomeDir()
	require.NoError(t, err)

	assert.Equal(t, filepath.Join(home, ".config", "router-hosts", "client.toml"), paths[0])
}

func TestFindClientConfigFile_XDGPriority(t *testing.T) {
	// Create both XDG and ~/.config entries
	xdgDir := t.TempDir()
	homeDir := t.TempDir()

	writeClientConfig(t, xdgDir, `server_address = "xdg-server"`)
	writeClientConfig(t, filepath.Join(homeDir, ".config"), `server_address = "home-server"`)

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
	assert.Equal(t, "localhost:50051", cfg.ServerAddress)
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
		ServerAddress: "file-server",
	}
	applyClientEnv(cfg)

	assert.Equal(t, "env-server", cfg.ServerAddress)
	assert.Equal(t, "/env/cert", cfg.CertPath)
	assert.Equal(t, "/env/key", cfg.KeyPath)
	assert.Equal(t, "/env/ca", cfg.CACertPath)
}

func TestApplyClientOverrides(t *testing.T) {
	server := "override-server"
	cert := "/override/cert"

	cfg := &ClientConfig{
		ServerAddress: "original",
		CertPath:      "/original/cert",
		KeyPath:       "/original/key",
	}

	applyClientOverrides(cfg, &ClientConfigOverrides{
		ServerAddress: &server,
		CertPath:      &cert,
	})

	assert.Equal(t, "override-server", cfg.ServerAddress)
	assert.Equal(t, "/override/cert", cfg.CertPath)
	assert.Equal(t, "/original/key", cfg.KeyPath) // unchanged
}
