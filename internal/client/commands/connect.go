package commands

import (
	"github.com/fzymgc-house/router-hosts/internal/client"
	"github.com/fzymgc-house/router-hosts/internal/config"
	"github.com/samber/oops"
)

// newClientFromFlags builds a gRPC client using global CLI flags and config
// file resolution. CLI flags override env vars which override config file.
func newClientFromFlags() (*client.Client, error) {
	overrides := &config.ClientConfigOverrides{}

	if Flags.Server != "" {
		overrides.ServerAddress = &Flags.Server
	}
	if Flags.Cert != "" {
		overrides.CertPath = &Flags.Cert
	}
	if Flags.Key != "" {
		overrides.KeyPath = &Flags.Key
	}
	if Flags.CA != "" {
		overrides.CACertPath = &Flags.CA
	}

	cfg, err := config.LoadClientConfig(overrides)
	if err != nil {
		return nil, oops.Wrapf(err, "loading client config")
	}

	c, err := client.NewClient(cfg)
	if err != nil {
		return nil, oops.Wrapf(err, "connecting to server")
	}

	return c, nil
}
