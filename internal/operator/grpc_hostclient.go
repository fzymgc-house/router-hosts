package operator

import (
	"context"
	"errors"
	"io"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
	"github.com/fzymgc-house/router-hosts/internal/client"
	"github.com/fzymgc-house/router-hosts/internal/config"
	"github.com/samber/oops"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrHostAlreadyExists is a sentinel returned by AddHost when the server
// reports that a host with the same IP and hostname already exists
// (gRPC AlreadyExists). Callers use errors.Is to detect this case and
// adopt the existing entry rather than retrying the create indefinitely.
var ErrHostAlreadyExists = errors.New("host already exists")

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
// Returns an error wrapping ErrHostAlreadyExists when the server responds with
// gRPC AlreadyExists; all other errors are wrapped with oops context.
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
		if status.Code(err) == codes.AlreadyExists {
			return "", oops.Wrapf(ErrHostAlreadyExists, "adding host %s/%s", ip, hostname)
		}
		return "", oops.Wrapf(err, "adding host %s/%s", ip, hostname)
	}
	return resp.GetId(), nil
}

// FindHost implements HostClient by querying SearchHosts and exact-matching
// on both IP and hostname. Returns nil, nil when no matching entry exists.
func (g *grpcHostClient) FindHost(ctx context.Context, ip, hostname string) (*HostEntry, error) {
	// Cancel the server stream promptly on early return (exact match found)
	// so the server stops sending remaining results.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := g.c.Hosts.SearchHosts(ctx, &hostsv1.SearchHostsRequest{Query: hostname})
	if err != nil {
		return nil, oops.Wrapf(err, "searching for host %s/%s", ip, hostname)
	}
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		if err != nil {
			return nil, oops.Wrapf(err, "receiving search results for host %s/%s", ip, hostname)
		}
		entry := resp.GetEntry()
		if entry == nil {
			continue
		}
		// SearchHosts performs contains/prefix matching — exact-match both
		// fields client-side to avoid adopting the wrong host.
		if entry.GetIpAddress() == ip && entry.GetHostname() == hostname {
			return &HostEntry{
				ID:       entry.GetId(),
				IP:       entry.GetIpAddress(),
				Hostname: entry.GetHostname(),
				Aliases:  entry.GetAliases(),
				Tags:     entry.GetTags(),
				Version:  entry.GetVersion(),
			}, nil
		}
	}
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
