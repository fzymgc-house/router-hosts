package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeConfigFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	err := os.WriteFile(path, []byte(content), 0o600)
	require.NoError(t, err)
	return path
}

const minimalConfig = `
[server]
bind_address = "0.0.0.0:50051"
hosts_file_path = "/etc/hosts"

[tls]
cert_path = "/etc/router-hosts/server.crt"
key_path = "/etc/router-hosts/server.key"
ca_cert_path = "/etc/router-hosts/ca.crt"
`

func TestLoadServerConfig_Minimal(t *testing.T) {
	path := writeConfigFile(t, minimalConfig)
	cfg, err := LoadServerConfig(path)
	require.NoError(t, err)

	assert.Equal(t, "0.0.0.0:50051", cfg.Server.BindAddress)
	assert.Equal(t, "/etc/hosts", cfg.Server.HostsFilePath)
	assert.Equal(t, "/etc/router-hosts/server.crt", cfg.TLS.CertPath)
	assert.Equal(t, "/etc/router-hosts/server.key", cfg.TLS.KeyPath)
	assert.Equal(t, "/etc/router-hosts/ca.crt", cfg.TLS.CACertPath)
}

func TestLoadServerConfig_RetentionDefaults(t *testing.T) {
	path := writeConfigFile(t, minimalConfig)
	cfg, err := LoadServerConfig(path)
	require.NoError(t, err)

	assert.Equal(t, DefaultMaxSnapshots, cfg.Retention.MaxSnapshots)
	assert.Equal(t, DefaultMaxAgeDays, cfg.Retention.MaxAgeDays)
}

func TestLoadServerConfig_CustomRetention(t *testing.T) {
	content := minimalConfig + `
[retention]
max_snapshots = 100
max_age_days = 60
`
	path := writeConfigFile(t, content)
	cfg, err := LoadServerConfig(path)
	require.NoError(t, err)

	assert.Equal(t, 100, cfg.Retention.MaxSnapshots)
	assert.Equal(t, 60, cfg.Retention.MaxAgeDays)
}

func TestLoadServerConfig_MissingBindAddress(t *testing.T) {
	content := `
[server]
bind_address = ""
hosts_file_path = "/etc/hosts"

[tls]
cert_path = "/cert.pem"
key_path = "/key.pem"
ca_cert_path = "/ca.pem"
`
	path := writeConfigFile(t, content)
	_, err := LoadServerConfig(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bind_address is required")
}

func TestLoadServerConfig_MissingHostsFilePath(t *testing.T) {
	content := `
[server]
bind_address = "0.0.0.0:50051"
hosts_file_path = ""

[tls]
cert_path = "/cert.pem"
key_path = "/key.pem"
ca_cert_path = "/ca.pem"
`
	path := writeConfigFile(t, content)
	_, err := LoadServerConfig(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hosts_file_path is required")
}

func TestLoadServerConfig_DatabasePath(t *testing.T) {
	content := minimalConfig + `
[database]
path = "/var/lib/router-hosts/hosts.db"
`
	path := writeConfigFile(t, content)
	cfg, err := LoadServerConfig(path)
	require.NoError(t, err)

	dbPath, err := cfg.Database.ResolveDBPath()
	require.NoError(t, err)
	assert.Equal(t, "/var/lib/router-hosts/hosts.db", dbPath)
}

func TestDatabaseConfig_DefaultPath(t *testing.T) {
	cfg := DatabaseConfig{}
	dbPath, err := cfg.ResolveDBPath()
	require.NoError(t, err)
	assert.Contains(t, dbPath, "router-hosts")
	assert.True(t, filepath.IsAbs(dbPath))
}

func TestDefaultDBPath_Platform(t *testing.T) {
	dbPath, err := DefaultDBPath()
	require.NoError(t, err)

	assert.Contains(t, dbPath, "router-hosts")
	assert.Contains(t, dbPath, "hosts.db")
	assert.True(t, filepath.IsAbs(dbPath))

	if runtime.GOOS == "darwin" {
		assert.Contains(t, dbPath, "Application Support")
	}
}

func TestLoadServerConfig_WithHooks(t *testing.T) {
	content := minimalConfig + `
[[hooks.on_success]]
name = "reload-dns"
command = "systemctl reload dnsmasq"

[[hooks.on_failure]]
name = "alert-ops"
command = "/usr/local/bin/alert-failure"
`
	path := writeConfigFile(t, content)
	cfg, err := LoadServerConfig(path)
	require.NoError(t, err)

	require.Len(t, cfg.Hooks.OnSuccess, 1)
	assert.Equal(t, "reload-dns", cfg.Hooks.OnSuccess[0].Name)
	assert.Equal(t, "systemctl reload dnsmasq", cfg.Hooks.OnSuccess[0].Command)

	require.Len(t, cfg.Hooks.OnFailure, 1)
	assert.Equal(t, "alert-ops", cfg.Hooks.OnFailure[0].Name)
}

func TestLoadServerConfig_InvalidHookName(t *testing.T) {
	content := minimalConfig + `
[[hooks.on_success]]
name = "Invalid Hook Name"
command = "echo test"
`
	path := writeConfigFile(t, content)
	_, err := LoadServerConfig(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kebab-case")
}

func TestLoadServerConfig_DuplicateHookNames(t *testing.T) {
	content := minimalConfig + `
[[hooks.on_success]]
name = "reload-dns"
command = "cmd1"

[[hooks.on_success]]
name = "reload-dns"
command = "cmd2"
`
	path := writeConfigFile(t, content)
	_, err := LoadServerConfig(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate")
}

func TestLoadServerConfig_EmptyHookCommand(t *testing.T) {
	content := minimalConfig + `
[[hooks.on_success]]
name = "reload-dns"
command = ""
`
	path := writeConfigFile(t, content)
	_, err := LoadServerConfig(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty or whitespace-only command")
}

func TestLoadServerConfig_HookNameTooLong(t *testing.T) {
	longName := ""
	for i := 0; i < 51; i++ {
		longName += "a"
	}
	content := minimalConfig + `
[[hooks.on_success]]
name = "` + longName + `"
command = "echo test"
`
	path := writeConfigFile(t, content)
	_, err := LoadServerConfig(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "character limit")
}

func TestLoadServerConfig_SameNameDifferentHookTypesAllowed(t *testing.T) {
	content := minimalConfig + `
[[hooks.on_success]]
name = "notify"
command = "notify-success"

[[hooks.on_failure]]
name = "notify"
command = "notify-failure"
`
	path := writeConfigFile(t, content)
	cfg, err := LoadServerConfig(path)
	require.NoError(t, err)
	assert.Len(t, cfg.Hooks.OnSuccess, 1)
	assert.Len(t, cfg.Hooks.OnFailure, 1)
}

func TestIsValidKebabCase(t *testing.T) {
	valid := []string{"reload-dns", "log-success", "alert-ops-team", "a", "abc123", "reload2dns"}
	for _, s := range valid {
		assert.True(t, isValidKebabCase(s), "expected valid: %q", s)
	}

	invalid := []string{"", "Reload-DNS", "reload_dns", "reload--dns", "-reload", "reload-", "reload dns", "reload.dns"}
	for _, s := range invalid {
		assert.False(t, isValidKebabCase(s), "expected invalid: %q", s)
	}
}

func TestLoadServerConfig_WithMetricsOTel(t *testing.T) {
	content := minimalConfig + `
[metrics.otel]
endpoint = "http://otel-collector:4317"
service_name = "my-router-hosts"
`
	path := writeConfigFile(t, content)
	cfg, err := LoadServerConfig(path)
	require.NoError(t, err)
	require.NotNil(t, cfg.Metrics)
	require.NotNil(t, cfg.Metrics.OTel)
	assert.Equal(t, "http://otel-collector:4317", cfg.Metrics.OTel.Endpoint)
	assert.Equal(t, "my-router-hosts", cfg.Metrics.OTel.ServiceName)
	assert.True(t, *cfg.Metrics.OTel.ExportMetrics)
	assert.True(t, *cfg.Metrics.OTel.ExportTraces)
	assert.Equal(t, DefaultExportIntervalSecs, cfg.Metrics.OTel.ExportIntervalSec)
}

func TestLoadServerConfig_MetricsNilWhenAbsent(t *testing.T) {
	path := writeConfigFile(t, minimalConfig)
	cfg, err := LoadServerConfig(path)
	require.NoError(t, err)
	assert.Nil(t, cfg.Metrics)
}

func TestLoadServerConfig_OTelDefaults(t *testing.T) {
	content := minimalConfig + `
[metrics.otel]
endpoint = "http://localhost:4317"
`
	path := writeConfigFile(t, content)
	cfg, err := LoadServerConfig(path)
	require.NoError(t, err)

	otel := cfg.Metrics.OTel
	assert.Equal(t, "router-hosts", otel.ServiceName)
	assert.True(t, *otel.ExportMetrics)
	assert.True(t, *otel.ExportTraces)
	assert.Equal(t, 60, otel.ExportIntervalSec)
	assert.Empty(t, otel.Headers)
}

func TestLoadServerConfig_OTelCustomInterval(t *testing.T) {
	content := minimalConfig + `
[metrics.otel]
endpoint = "http://localhost:4317"
export_interval_secs = 30
`
	path := writeConfigFile(t, content)
	cfg, err := LoadServerConfig(path)
	require.NoError(t, err)
	assert.Equal(t, 30, cfg.Metrics.OTel.ExportIntervalSec)
}

func TestLoadServerConfig_OTelHeaders(t *testing.T) {
	content := minimalConfig + `
[metrics.otel]
endpoint = "http://localhost:4317"
headers = { "Authorization" = "Bearer token123" }
`
	path := writeConfigFile(t, content)
	cfg, err := LoadServerConfig(path)
	require.NoError(t, err)
	assert.Equal(t, "Bearer token123", cfg.Metrics.OTel.Headers["Authorization"])
}

func TestLoadServerConfig_FileNotFound(t *testing.T) {
	_, err := LoadServerConfig("/nonexistent/config.toml")
	require.Error(t, err)
}

func TestLoadServerConfig_InvalidTOML(t *testing.T) {
	path := writeConfigFile(t, "this is not valid toml {{{}}")
	_, err := LoadServerConfig(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse config")
}

func TestLoadServerConfig_WorldWritableRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission checks not applicable on Windows")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	err := os.WriteFile(path, []byte(minimalConfig), 0o600)
	require.NoError(t, err)
	// Explicitly set world-writable to bypass umask
	require.NoError(t, os.Chmod(path, 0o666))

	_, err = LoadServerConfig(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "world-writable")
}

func TestLoadServerConfig_SecurePermissionsAccepted(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission checks not applicable on Windows")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	err := os.WriteFile(path, []byte(minimalConfig), 0o600)
	require.NoError(t, err)

	cfg, err := LoadServerConfig(path)
	require.NoError(t, err)
	assert.Equal(t, "0.0.0.0:50051", cfg.Server.BindAddress)
}

func TestHookDefinition_Validate(t *testing.T) {
	tests := []struct {
		name    string
		hook    HookDefinition
		wantErr string
	}{
		{
			name: "valid",
			hook: HookDefinition{Name: "reload-dns", Command: "systemctl reload dnsmasq"},
		},
		{
			name:    "empty name",
			hook:    HookDefinition{Name: "", Command: "echo test"},
			wantErr: "non-empty",
		},
		{
			name:    "whitespace-only command",
			hook:    HookDefinition{Name: "test-hook", Command: "   \t\n  "},
			wantErr: "empty or whitespace-only",
		},
		{
			name:    "name exactly 50 chars",
			hook:    HookDefinition{Name: "aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeee", Command: "echo"},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.hook.validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestExpandEnvVars_Simple(t *testing.T) {
	t.Setenv("TEST_EXPAND_VAR", "hello-world")
	result, err := ExpandEnvVars("${TEST_EXPAND_VAR}")
	require.NoError(t, err)
	assert.Equal(t, "hello-world", result)
}

func TestExpandEnvVars_Default(t *testing.T) {
	// Use a variable name that is extremely unlikely to exist
	result, err := ExpandEnvVars("${TEST_EXPAND_MISSING_2ae7c1b4:-fallback-value}")
	require.NoError(t, err)
	assert.Equal(t, "fallback-value", result)
}

func TestExpandEnvVars_DefaultUsedWhenEmpty(t *testing.T) {
	t.Setenv("TEST_EXPAND_EMPTY", "")
	result, err := ExpandEnvVars("${TEST_EXPAND_EMPTY:-default-val}")
	require.NoError(t, err)
	assert.Equal(t, "default-val", result)
}

func TestExpandEnvVars_Missing(t *testing.T) {
	// Use a variable name that is extremely unlikely to exist
	_, err := ExpandEnvVars("${TEST_EXPAND_DOES_NOT_EXIST_9f3a0b2c}")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not set")
}

func TestExpandEnvVars_Escape(t *testing.T) {
	result, err := ExpandEnvVars("price is $$100")
	require.NoError(t, err)
	assert.Equal(t, "price is $100", result)
}

func TestExpandEnvVars_Multiple(t *testing.T) {
	t.Setenv("TEST_EXPAND_A", "alpha")
	t.Setenv("TEST_EXPAND_B", "beta")

	result, err := ExpandEnvVars("${TEST_EXPAND_A}-${TEST_EXPAND_B}")
	require.NoError(t, err)
	assert.Equal(t, "alpha-beta", result)
}

func TestExpandEnvVars_NoVars(t *testing.T) {
	result, err := ExpandEnvVars("plain string with no vars")
	require.NoError(t, err)
	assert.Equal(t, "plain string with no vars", result)
}

func TestExpandEnvVars_UnclosedBrace(t *testing.T) {
	_, err := ExpandEnvVars("${UNCLOSED")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unclosed")
}

func TestACMEConfig_Validation(t *testing.T) {
	base := func() Config {
		return Config{
			Server: ServerConfig{BindAddress: "0.0.0.0:50051", HostsFilePath: "/etc/hosts"},
			TLS: TLSConfig{
				CertPath:   "/cert.pem",
				KeyPath:    "/key.pem",
				CACertPath: "/ca.pem",
				ACME: &ACMEConfig{
					Enabled:      true,
					Email:        "test@example.com",
					Domains:      []string{"example.com"},
					DNS:          ACMEDNSConfig{Provider: "cloudflare", Cloudflare: &CloudflareDNS{APIToken: "tok"}},
					RenewalDays:  30,
					DirectoryURL: "https://acme.example.com",
				},
			},
		}
	}

	t.Run("valid", func(t *testing.T) {
		cfg := base()
		assert.NoError(t, cfg.validate())
	})

	t.Run("missing email", func(t *testing.T) {
		cfg := base()
		cfg.TLS.ACME.Email = ""
		err := cfg.validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "email is required")
	})

	t.Run("missing domains", func(t *testing.T) {
		cfg := base()
		cfg.TLS.ACME.Domains = nil
		err := cfg.validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least one domain")
	})

	t.Run("unsupported provider", func(t *testing.T) {
		cfg := base()
		cfg.TLS.ACME.DNS.Provider = "route53"
		err := cfg.validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cloudflare")
	})

	t.Run("missing cloudflare section", func(t *testing.T) {
		cfg := base()
		cfg.TLS.ACME.DNS.Cloudflare = nil
		err := cfg.validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cloudflare section is required")
	})

	t.Run("missing api token", func(t *testing.T) {
		cfg := base()
		cfg.TLS.ACME.DNS.Cloudflare.APIToken = ""
		err := cfg.validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "api_token is required")
	})

	t.Run("disabled skips validation", func(t *testing.T) {
		cfg := base()
		cfg.TLS.ACME.Enabled = false
		cfg.TLS.ACME.Email = "" // would fail if enabled
		assert.NoError(t, cfg.validate())
	})

	t.Run("nil ACME skips validation", func(t *testing.T) {
		cfg := base()
		cfg.TLS.ACME = nil
		assert.NoError(t, cfg.validate())
	})
}

func TestLoadServerConfig_WithACME(t *testing.T) {
	content := minimalConfig + `
[tls.acme]
enabled = true
directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
email = "admin@example.com"
domains = ["example.com", "www.example.com"]
storage_path = "/var/lib/router-hosts/acme"

[tls.acme.dns]
provider = "cloudflare"

[tls.acme.dns.cloudflare]
api_token = "my-token"
`
	path := writeConfigFile(t, content)
	cfg, err := LoadServerConfig(path)
	require.NoError(t, err)

	require.NotNil(t, cfg.TLS.ACME)
	assert.True(t, cfg.TLS.ACME.Enabled)
	assert.Equal(t, "admin@example.com", cfg.TLS.ACME.Email)
	assert.Equal(t, []string{"example.com", "www.example.com"}, cfg.TLS.ACME.Domains)
	assert.Equal(t, DefaultRenewalDays, cfg.TLS.ACME.RenewalDays)
	assert.Equal(t, DefaultCheckInterval, cfg.TLS.ACME.CheckInterval)
	assert.Equal(t, "cloudflare", cfg.TLS.ACME.DNS.Provider)
	assert.Equal(t, "my-token", cfg.TLS.ACME.DNS.Cloudflare.APIToken)
}

func TestLoadServerConfig_ACMEDefaults(t *testing.T) {
	content := minimalConfig + `
[tls.acme]
enabled = true
email = "admin@example.com"
domains = ["example.com"]

[tls.acme.dns]
provider = "cloudflare"

[tls.acme.dns.cloudflare]
api_token = "tok"
`
	path := writeConfigFile(t, content)
	cfg, err := LoadServerConfig(path)
	require.NoError(t, err)

	assert.Equal(t, LetsEncryptProductionURL, cfg.TLS.ACME.DirectoryURL)
	assert.Equal(t, DefaultRenewalDays, cfg.TLS.ACME.RenewalDays)
	assert.Equal(t, DefaultCheckInterval, cfg.TLS.ACME.CheckInterval)
}
