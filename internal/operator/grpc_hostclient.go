package operator

import (
	"context"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
	"github.com/fzymgc-house/router-hosts/internal/client"
	"github.com/fzymgc-house/router-hosts/internal/config"
	"github.com/samber/oops"
)

// grpcHostClient adapts the project's gRPC client to the HostClient interface.
type grpcHostClient struct {
	c *client.Client
}

// NewGRPCHostClient creates a HostClient backed by the router-hosts gRPC
// service. When certPath/keyPath/caCertPath are empty, the client connects
// without mTLS (useful for development).
func NewGRPCHostClient(serverAddr, certPath, keyPath, caCertPath string) (HostClient, error) {
	cfg := &config.ClientConfig{
		Server: config.ClientServerConfig{Address: serverAddr},
		TLS:    config.ClientTLSConfig{CertPath: certPath, KeyPath: keyPath, CACertPath: caCertPath},
	}

	c, err := client.NewClient(cfg)
	if err != nil {
		return nil, oops.Wrapf(err, "creating gRPC client for operator")
	}
	return &grpcHostClient{c: c}, nil
}

// Close implements HostClient.
func (g *grpcHostClient) Close() error {
	return g.c.Close()
}

// AddHost implements HostClient.
func (g *grpcHostClient) AddHost(ctx context.Context, ip, hostname, comment string, aliases, tags []string) (string, error) {
	var commentPtr *string
	if comment != "" {
		commentPtr = &comment
	}

	resp, err := g.c.Hosts.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: ip,
		Hostname:  hostname,
		Comment:   commentPtr,
		Aliases:   aliases,
		Tags:      tags,
	})
	if err != nil {
		return "", oops.Wrapf(err, "adding host %s/%s", ip, hostname)
	}
	return resp.GetId(), nil
}

// UpdateHost implements HostClient.
func (g *grpcHostClient) UpdateHost(ctx context.Context, id, ip, hostname, comment string, aliases, tags []string, version string) error {
	req := &hostsv1.UpdateHostRequest{
		Id:        id,
		IpAddress: &ip,
		Hostname:  &hostname,
	}
	if comment != "" {
		req.Comment = &comment
	}
	if version != "" {
		req.ExpectedVersion = &version
	}
	if aliases != nil {
		req.Aliases = &hostsv1.AliasesUpdate{Values: aliases}
	}
	if tags != nil {
		req.Tags = &hostsv1.TagsUpdate{Values: tags}
	}

	_, err := g.c.Hosts.UpdateHost(ctx, req)
	if err != nil {
		return oops.Wrapf(err, "updating host %s", id)
	}
	return nil
}

// DeleteHost implements HostClient.
func (g *grpcHostClient) DeleteHost(ctx context.Context, id string) error {
	_, err := g.c.Hosts.DeleteHost(ctx, &hostsv1.DeleteHostRequest{Id: id})
	if err != nil {
		return oops.Wrapf(err, "deleting host %s", id)
	}
	return nil
}

// GetHost implements HostClient.
func (g *grpcHostClient) GetHost(ctx context.Context, id string) (*HostEntry, error) {
	resp, err := g.c.Hosts.GetHost(ctx, &hostsv1.GetHostRequest{Id: id})
	if err != nil {
		return nil, oops.Wrapf(err, "getting host %s", id)
	}
	entry := resp.GetEntry()
	if entry == nil {
		return nil, oops.Errorf("empty response for host %s", id)
	}

	return &HostEntry{
		ID:       entry.GetId(),
		IP:       entry.GetIpAddress(),
		Hostname: entry.GetHostname(),
		Aliases:  entry.GetAliases(),
		Tags:     entry.GetTags(),
		Version:  entry.GetVersion(),
	}, nil
}
