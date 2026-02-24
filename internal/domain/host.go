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
	Version   int64     `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	// Deleted is set to true by the projection when replaying a HostDeleted
	// event. Entries with Deleted=true act as tombstones: they are retained in
	// the projection store so that event replay remains idempotent, but are
	// excluded from all query results returned to callers (ListAll, Search,
	// GetAtTime, etc.). External callers should never observe Deleted=true.
	Deleted bool `json:"deleted"`
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

// Validate checks that non-nil pattern fields are non-empty strings.
func (f SearchFilter) Validate() error {
	if f.IPPattern != nil && *f.IPPattern == "" {
		return ErrValidation("ip_pattern must not be an empty string; omit the field to match all IPs")
	}
	if f.HostnamePattern != nil && *f.HostnamePattern == "" {
		return ErrValidation("hostname_pattern must not be an empty string; omit the field to match all hostnames")
	}
	if f.Query != nil && *f.Query == "" {
		return ErrValidation("query must not be an empty string; omit the field to return all entries")
	}
	return nil
}
