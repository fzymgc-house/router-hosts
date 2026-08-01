package client

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"time"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
	"github.com/fzymgc-house/router-hosts/internal/config"
	"github.com/samber/oops"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

// KeepaliveParams returns the gRPC keepalive.ClientParameters this client
// applies to every connection NewClient creates — every `router-hosts` CLI
// command, not only long-lived sinks. Pings continue during quiet periods
// (PermitWithoutStream), so a partitioned connection surfaces within tens of
// seconds instead of grpc-go's default two-hour interval (T-1-13). Time must
// stay at or above internal/server.KeepaliveEnforcementPolicy().MinTime, or a
// compliant client is sent GOAWAY for pinging too often.
func KeepaliveParams() keepalive.ClientParameters {
	return keepalive.ClientParameters{
		Time:                20 * time.Second,
		Timeout:             10 * time.Second,
		PermitWithoutStream: true,
	}
}

// Client wraps a gRPC connection and provides the HostsService client.
type Client struct {
	conn    *grpc.ClientConn
	Hosts   hostsv1.HostsServiceClient
	address string

	// maxStreamEntries and maxStreamBytes are the stream-collection bounds
	// (D-14, TMPL-07) this client reports to every collecting call site.
	// Zero means "unset" and falls back to the config package default via
	// MaxStreamEntries/MaxStreamBytes, so a Client built by
	// NewClientFromConn (bufconn test path) is exercised through the same
	// bounded path production traffic is.
	maxStreamEntries int
	maxStreamBytes   int64
}

// Option configures optional Client behavior applied after construction.
// Its sole purpose is the pinned test seam for TMPL-07 (review L6): a test
// drives the fail-loud stream-collection refusal path with a small ceiling
// via WithMaxStreamEntries/WithMaxStreamBytes instead of seeding tens of
// thousands of host entries. Production callers configure limits through
// the client config file's [limits] table (or its environment variable
// overrides), not through Option.
type Option func(*Client)

// WithMaxStreamEntries overrides the entry-count ceiling every collecting
// call site enforces, regardless of how the Client was constructed or what
// [limits] configured. Intended for tests.
func WithMaxStreamEntries(n int) Option {
	return func(c *Client) { c.maxStreamEntries = n }
}

// WithMaxStreamBytes overrides the serialized-byte-size ceiling every
// collecting call site enforces, regardless of how the Client was
// constructed or what [limits] configured. Intended for tests.
func WithMaxStreamBytes(n int64) Option {
	return func(c *Client) { c.maxStreamBytes = n }
}

// MaxStreamEntries returns the entry-count ceiling every collecting call
// site (host list, host search, snapshot list, render) enforces before
// refusing a response outright. Falls back to config.DefaultMaxStreamEntries
// when unset.
func (c *Client) MaxStreamEntries() int {
	if c.maxStreamEntries == 0 {
		return config.DefaultMaxStreamEntries
	}
	return c.maxStreamEntries
}

// MaxStreamBytes returns the serialized-byte-size ceiling every collecting
// call site enforces before refusing a response outright. Falls back to
// config.DefaultMaxStreamBytes when unset.
func (c *Client) MaxStreamBytes() int64 {
	if c.maxStreamBytes == 0 {
		return config.DefaultMaxStreamBytes
	}
	return c.maxStreamBytes
}

// NewClient creates a gRPC client from the resolved ClientConfig.
// TLS configuration is required; all three paths (cert_path, key_path,
// ca_cert_path) must be set in the config. Options, when provided, are
// applied last and win over cfg.Limits (see Option).
func NewClient(cfg *config.ClientConfig, opts ...Option) (*Client, error) {
	creds, err := buildTransportCredentials(cfg)
	if err != nil {
		return nil, oops.Wrapf(err, "building transport credentials")
	}

	conn, err := grpc.NewClient(
		cfg.Server.Address,
		grpc.WithTransportCredentials(creds),
		grpc.WithKeepaliveParams(KeepaliveParams()),
	)
	if err != nil {
		return nil, oops.Wrapf(err, "dialing gRPC server %s", cfg.Server.Address)
	}

	c := &Client{
		conn:             conn,
		Hosts:            hostsv1.NewHostsServiceClient(conn),
		address:          cfg.Server.Address,
		maxStreamEntries: cfg.Limits.MaxStreamEntries,
		maxStreamBytes:   cfg.Limits.MaxStreamBytes,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

// NewClientFromConn creates a Client from an existing gRPC connection.
// The returned client does NOT own the connection: calling Close is a no-op.
// This is primarily useful for testing with bufconn where the connection
// lifecycle is managed externally. Options, when provided, are applied last
// (see Option).
func NewClientFromConn(conn *grpc.ClientConn, opts ...Option) *Client {
	c := &Client{
		// conn is intentionally nil so Close() is a no-op.
		// The caller retains ownership of the connection.
		Hosts: hostsv1.NewHostsServiceClient(conn),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Close releases the underlying gRPC connection.
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// Address returns the server address this client is connected to.
func (c *Client) Address() string {
	return c.address
}

// buildTransportCredentials creates TLS credentials from config paths.
// All three paths must be provided; insecure connections are not supported.
func buildTransportCredentials(cfg *config.ClientConfig) (credentials.TransportCredentials, error) {
	if (cfg.TLS.CertPath != "" && cfg.TLS.KeyPath == "") || (cfg.TLS.CertPath == "" && cfg.TLS.KeyPath != "") {
		return nil, oops.Errorf("cert_path and key_path must both be set or both be empty")
	}

	if cfg.TLS.CertPath == "" && cfg.TLS.KeyPath == "" && cfg.TLS.CACertPath == "" {
		return nil, oops.Errorf("TLS configuration required: set cert_path, key_path, and ca_cert_path")
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	// Load client certificate for mTLS
	if cfg.TLS.CertPath != "" && cfg.TLS.KeyPath != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLS.CertPath, cfg.TLS.KeyPath)
		if err != nil {
			return nil, oops.Wrapf(err, "loading client certificate")
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	// Load CA certificate for server verification
	if cfg.TLS.CACertPath != "" {
		caCert, err := os.ReadFile(cfg.TLS.CACertPath)
		if err != nil {
			return nil, oops.Wrapf(err, "reading CA certificate")
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, oops.Errorf("failed to parse CA certificate from %s", cfg.TLS.CACertPath)
		}
		tlsCfg.RootCAs = pool
	}

	return credentials.NewTLS(tlsCfg), nil
}
