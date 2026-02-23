package sqlite

import (
	"context"
	"fmt"
	"strings"
	"time"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"

	"github.com/oklog/ulid/v2"
	"github.com/samber/oops"

	"github.com/fzymgc-house/router-hosts/internal/domain"
)

// ListAll returns all non-deleted host entries by replaying events.
func (s *Storage) ListAll(ctx context.Context) ([]domain.HostEntry, error) {
	var entries []domain.HostEntry
	err := s.withConn(ctx, func(conn *sqlite.Conn) error {
		aggIDs, err := getDistinctAggregateIDs(conn)
		if err != nil {
			return err
		}
		for _, aggID := range aggIDs {
			events, loadErr := loadEventsForAggregate(conn, aggID)
			if loadErr != nil {
				return loadErr
			}
			entry, replayErr := replayEvents(aggID, events)
			if replayErr != nil {
				return replayErr
			}
			if entry != nil && !entry.Deleted {
				entries = append(entries, *entry)
			}
		}
		return nil
	})
	return entries, err
}

// GetByID returns a single host entry by replaying its events.
func (s *Storage) GetByID(ctx context.Context, id ulid.ULID) (*domain.HostEntry, error) {
	var entry *domain.HostEntry
	err := s.withConn(ctx, func(conn *sqlite.Conn) error {
		events, loadErr := loadEventsForAggregate(conn, id)
		if loadErr != nil {
			return loadErr
		}
		if len(events) == 0 {
			return domain.ErrNotFound("host", id.String())
		}
		var replayErr error
		entry, replayErr = replayEvents(id, events)
		if replayErr != nil {
			return replayErr
		}
		if entry == nil || entry.Deleted {
			return domain.ErrNotFound("host", id.String())
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return entry, nil
}

// FindByIPAndHostname finds a host entry matching the given IP and hostname.
// Note: This is O(n) — it scans all events for all aggregates via ListAll and linearly searches them.
// For better performance on large datasets, consider indexing by IP+hostname in the event store.
func (s *Storage) FindByIPAndHostname(ctx context.Context, ip, hostname string) (*domain.HostEntry, error) {
	entries, err := s.ListAll(ctx)
	if err != nil {
		return nil, err
	}
	for i := range entries {
		if entries[i].IP == ip && entries[i].Hostname == hostname {
			return &entries[i], nil
		}
	}
	return nil, domain.ErrNotFound("host", fmt.Sprintf("%s/%s", ip, hostname))
}

// Search filters host entries using the provided search filter.
func (s *Storage) Search(ctx context.Context, filter domain.SearchFilter) ([]domain.HostEntry, error) {
	entries, err := s.ListAll(ctx)
	if err != nil {
		return nil, err
	}

	if filter.IsEmpty() {
		return entries, nil
	}

	var results []domain.HostEntry
	for _, entry := range entries {
		if matchesFilter(entry, filter) {
			results = append(results, entry)
		}
	}
	return results, nil
}

// GetAtTime returns the state of all hosts at a specific point in time.
func (s *Storage) GetAtTime(ctx context.Context, at time.Time) ([]domain.HostEntry, error) {
	var entries []domain.HostEntry
	err := s.withConn(ctx, func(conn *sqlite.Conn) error {
		aggIDs, getErr := getDistinctAggregateIDs(conn)
		if getErr != nil {
			return getErr
		}
		for _, aggID := range aggIDs {
			events, loadErr := loadEventsForAggregate(conn, aggID)
			if loadErr != nil {
				return loadErr
			}

			// Filter events to only those created at or before the target time.
			var filtered []domain.EventEnvelope
			for _, env := range events {
				if !env.CreatedAt.After(at) {
					filtered = append(filtered, env)
				}
			}

			if len(filtered) == 0 {
				continue
			}

			entry, replayErr := replayEvents(aggID, filtered)
			if replayErr != nil {
				return replayErr
			}
			if entry != nil && !entry.Deleted {
				entries = append(entries, *entry)
			}
		}
		return nil
	})
	return entries, err
}

// replayEvents applies events sequentially to build a HostEntry.
// This is the core of the event sourcing pattern.
func replayEvents(aggregateID ulid.ULID, events []domain.EventEnvelope) (*domain.HostEntry, error) {
	if len(events) == 0 {
		return nil, nil
	}

	var entry *domain.HostEntry

	for _, env := range events {
		decoded, err := env.Event.Decode()
		if err != nil {
			return nil, oops.Wrapf(err, "decode event %s for aggregate %s", env.EventID, aggregateID)
		}

		switch ev := decoded.(type) {
		case domain.HostCreated:
			entry = &domain.HostEntry{
				ID:        aggregateID,
				IP:        ev.IPAddress,
				Hostname:  ev.Hostname,
				Aliases:   ev.Aliases,
				Comment:   ev.Comment,
				Tags:      ev.Tags,
				CreatedAt: ev.CreatedAt,
				UpdatedAt: env.CreatedAt,
				Version:   env.Version,
			}

		case domain.IPAddressChanged:
			if entry != nil {
				entry.IP = ev.NewIP
				entry.UpdatedAt = env.CreatedAt
				entry.Version = env.Version
			}

		case domain.HostnameChanged:
			if entry != nil {
				entry.Hostname = ev.NewHostname
				entry.UpdatedAt = env.CreatedAt
				entry.Version = env.Version
			}

		case domain.CommentUpdated:
			if entry != nil {
				entry.Comment = ev.NewComment
				entry.UpdatedAt = env.CreatedAt
				entry.Version = env.Version
			}

		case domain.TagsModified:
			if entry != nil {
				entry.Tags = ev.NewTags
				entry.UpdatedAt = env.CreatedAt
				entry.Version = env.Version
			}

		case domain.AliasesModified:
			if entry != nil {
				entry.Aliases = ev.NewAliases
				entry.UpdatedAt = env.CreatedAt
				entry.Version = env.Version
			}

		case domain.HostDeleted:
			if entry != nil {
				entry.Deleted = true
				entry.UpdatedAt = env.CreatedAt
				entry.Version = env.Version
			}

		case domain.HostImported:
			entry = &domain.HostEntry{
				ID:        aggregateID,
				IP:        ev.IPAddress,
				Hostname:  ev.Hostname,
				Aliases:   ev.Aliases,
				Comment:   ev.Comment,
				Tags:      ev.Tags,
				CreatedAt: ev.OccurredAt,
				UpdatedAt: env.CreatedAt,
				Version:   env.Version,
			}

		default:
			return nil, oops.Errorf("replayEvents: unhandled event type %q for aggregate %s", env.Event.Type, aggregateID)
		}
	}

	return entry, nil
}

// matchesFilter checks if a host entry matches the search filter criteria.
func matchesFilter(entry domain.HostEntry, filter domain.SearchFilter) bool {
	if filter.Query != nil {
		q := strings.ToLower(*filter.Query)
		matched := strings.Contains(strings.ToLower(entry.IP), q) ||
			strings.Contains(strings.ToLower(entry.Hostname), q)
		if entry.Comment != nil {
			matched = matched || strings.Contains(strings.ToLower(*entry.Comment), q)
		}
		for _, tag := range entry.Tags {
			matched = matched || strings.Contains(strings.ToLower(tag), q)
		}
		if !matched {
			return false
		}
	}

	if filter.IPPattern != nil {
		if !strings.HasPrefix(entry.IP, *filter.IPPattern) {
			return false
		}
	}

	if filter.HostnamePattern != nil {
		if !strings.Contains(strings.ToLower(entry.Hostname), strings.ToLower(*filter.HostnamePattern)) {
			return false
		}
	}

	if len(filter.Tags) > 0 {
		if !hasAnyTag(entry.Tags, filter.Tags) {
			return false
		}
	}

	return true
}

// hasAnyTag checks if the entry's tags contain any of the filter tags.
func hasAnyTag(entryTags, filterTags []string) bool {
	tagSet := make(map[string]struct{}, len(entryTags))
	for _, t := range entryTags {
		tagSet[t] = struct{}{}
	}
	for _, t := range filterTags {
		if _, ok := tagSet[t]; ok {
			return true
		}
	}
	return false
}

// getDistinctAggregateIDs returns all unique aggregate IDs from the events table.
func getDistinctAggregateIDs(conn *sqlite.Conn) ([]ulid.ULID, error) {
	var ids []ulid.ULID
	err := sqlitex.Execute(conn,
		`SELECT DISTINCT aggregate_id FROM events`,
		&sqlitex.ExecOptions{
			ResultFunc: func(stmt *sqlite.Stmt) error {
				id, parseErr := ulid.Parse(stmt.ColumnText(0))
				if parseErr != nil {
					return parseErr
				}
				ids = append(ids, id)
				return nil
			},
		})
	if err != nil {
		return nil, oops.Wrapf(err, "get aggregate ids")
	}
	return ids, nil
}

// loadEventsForAggregate reads all events for a single aggregate, ordered by version.
func loadEventsForAggregate(conn *sqlite.Conn, aggregateID ulid.ULID) ([]domain.EventEnvelope, error) {
	var events []domain.EventEnvelope
	err := sqlitex.Execute(conn,
		`SELECT event_id, aggregate_id, event_type, event_data, event_version, created_at, created_by
		 FROM events WHERE aggregate_id = ? ORDER BY event_version ASC`,
		&sqlitex.ExecOptions{
			Args: []any{aggregateID.String()},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				env, scanErr := scanEventEnvelope(stmt)
				if scanErr != nil {
					return scanErr
				}
				events = append(events, env)
				return nil
			},
		})
	if err != nil {
		return nil, oops.Wrapf(err, "load events for %s", aggregateID)
	}
	return events, nil
}
