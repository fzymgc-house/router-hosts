package client

import (
	"crypto/tls"
	"crypto/x509"
	"os"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
	"github.com/fzymgc-house/router-hosts/internal/config"
	"github.com/samber/oops"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Client wraps a gRPC connection and provides the HostsService client.
type Client struct {
	conn    *grpc.ClientConn
	Hosts   hostsv1.HostsServiceClient
	address string
}

// NewClient creates a gRPC client from the resolved ClientConfig.
// TLS configuration is required; all three paths (cert_path, key_path,
// ca_cert_path) must be set in the config.
func NewClient(cfg *config.ClientConfig) (*Client, error) {
	creds, err := buildTransportCredentials(cfg)
	if err != nil {
		return nil, oops.Wrapf(err, "building transport credentials")
	}

	conn, err := grpc.NewClient(
		cfg.Server.Address,
		grpc.WithTransportCredentials(creds),
	)
	if err != nil {
		return nil, oops.Wrapf(err, "dialing gRPC server %s", cfg.Server.Address)
	}

	return &Client{
		conn:    conn,
		Hosts:   hostsv1.NewHostsServiceClient(conn),
		address: cfg.Server.Address,
	}, nil
}

// NewClientFromConn creates a Client from an existing gRPC connection.
// The returned client does NOT own the connection: calling Close is a no-op.
// This is primarily useful for testing with bufconn where the connection
// lifecycle is managed externally.
func NewClientFromConn(conn *grpc.ClientConn) *Client {
	return &Client{
		// conn is intentionally nil so Close() is a no-op.
		// The caller retains ownership of the connection.
		Hosts: hostsv1.NewHostsServiceClient(conn),
	}
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
