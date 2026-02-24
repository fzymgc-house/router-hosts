package operator

import "context"

// HostEntry holds the server-side host entry data returned from the
// router-hosts gRPC server.
type HostEntry struct {
	ID       string
	IP       string
	Hostname string
	Aliases  []string
	Tags     []string
	Version  string
}

// HostClient abstracts the gRPC host operations needed by the operator
// reconcilers. Implementations wrap the real gRPC client; tests supply
// a mock.
type HostClient interface {
	// AddHost creates a new host entry and returns the server-assigned ID.
	AddHost(ctx context.Context, ip, hostname, comment string, aliases, tags []string) (string, error)

	// UpdateHost modifies an existing host entry identified by id.
	// version is the optimistic-concurrency version string from the
	// previous read.
	UpdateHost(ctx context.Context, id, ip, hostname, comment string, aliases, tags []string, version string) error

	// DeleteHost removes a host entry by its ID.
	DeleteHost(ctx context.Context, id string) error

	// GetHost retrieves a single host entry by ID.
	GetHost(ctx context.Context, id string) (*HostEntry, error)

	// Close releases any resources held by the client.
	Close() error
}
