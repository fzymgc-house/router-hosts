package domain

import (
	"time"

	"github.com/oklog/ulid/v2"
)

// HostEntry is the read-model projection of a host aggregate (CQRS query side).
type HostEntry struct {
	ID        ulid.ULID `json:"id"`
	IP        string    `json:"ip_address"`
	Hostname  string    `json:"hostname"`
	Aliases   []string  `json:"aliases"`
	Comment   *string   `json:"comment,omitempty"`
	Tags      []string  `json:"tags"`
	Version   string    `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Deleted   bool      `json:"deleted"`
}

// SearchFilter specifies criteria for querying host entries.
type SearchFilter struct {
	IPPattern       *string  `json:"ip_pattern,omitempty"`
	HostnamePattern *string  `json:"hostname_pattern,omitempty"`
	Tags            []string `json:"tags,omitempty"`
	Query           *string  `json:"query,omitempty"`
}

// IsEmpty returns true when no filter criteria are set.
func (f SearchFilter) IsEmpty() bool {
	return f.IPPattern == nil &&
		f.HostnamePattern == nil &&
		len(f.Tags) == 0 &&
		f.Query == nil
}
