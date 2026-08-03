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

// defaultListPageSize is the page size ListAll uses when draining ListPage
// internally. A package var, not a const, so tests can shrink it instead of
// seeding large fixtures — following the MaxTrackedSinks precedent
// (internal/server/sinkmetrics.go).
var defaultListPageSize = 500

// ListAll returns all non-deleted host entries by draining ListPage from the
// zero cursor (D-07). Kept for existing callers; new code should prefer
// ListPage directly. This is a thin wrapper: the two paths are definitionally
// the same ordering, since ListAll has no query logic of its own anymore.
func (s *Storage) ListAll(ctx context.Context) ([]domain.HostEntry, error) {
	var entries []domain.HostEntry
	var cursor ulid.ULID
	for {
		page, next, done, err := s.ListPage(ctx, cursor, defaultListPageSize)
		if err != nil {
			return nil, oops.Wrapf(err, "list all hosts")
		}
		entries = append(entries, page...)
		if done {
			break
		}
		cursor = next
	}
	return entries, nil
}

// ListPage returns a keyset page of live host entries. See
// storage.HostProjection.ListPage for the full ordering, fill-to-N,
// atomicity, and consistency contract this method implements.
func (s *Storage) ListPage(ctx context.Context, after ulid.ULID, limit int) (entries []domain.HostEntry, next ulid.ULID, done bool, err error) {
	if limit <= 0 {
		return nil, ulid.ULID{}, false, oops.Errorf("list host page after %s: limit must be positive, got %d", after, limit)
	}
	// Checked explicitly rather than relying solely on the pool's Take(ctx):
	// Take selects between an already-ready free connection and ctx.Done(),
	// and Go's select does not prefer either arm when both are ready, so an
	// already-cancelled context is not guaranteed to short-circuit a
	// same-instant Take. This check makes cancellation deterministic.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ulid.ULID{}, false, oops.Wrapf(ctxErr, "list host page after %s", after)
	}

	cursor := after
	err = s.withConn(ctx, func(conn *sqlite.Conn) error {
		for len(entries) < limit {
			ids, idErr := getAggregateIDPage(conn, cursor, limit-len(entries))
			if idErr != nil {
				return idErr
			}
			if len(ids) == 0 {
				done = true
				return nil
			}
			for _, id := range ids {
				cursor = id
				events, loadErr := loadEventsForAggregate(conn, id)
				if loadErr != nil {
					return loadErr
				}
				entry, replayErr := replayEvents(id, events)
				if replayErr != nil {
					return replayErr
				}
				if entry != nil && !entry.Deleted {
					entries = append(entries, *entry)
				}
				if len(entries) >= limit {
					break
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, ulid.ULID{}, false, oops.Wrapf(err, "list host page after %s", after)
	}
	return entries, cursor, done, nil
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

// pageLister matches ListPage's signature, narrowed to a function type so
// findByIPAndHostname's early-exit behavior can be exercised against a
// call-counting decorator in tests without a global hook (D-04).
type pageLister func(ctx context.Context, after ulid.ULID, limit int) (entries []domain.HostEntry, next ulid.ULID, done bool, err error)

// FindByIPAndHostname finds a host entry matching the given IP and hostname.
// Streams ListPage pages rather than draining the whole inventory first
// (D-04): returns as soon as a match is found, so pages after the match are
// never fetched.
func (s *Storage) FindByIPAndHostname(ctx context.Context, ip, hostname string) (*domain.HostEntry, error) {
	return findByIPAndHostname(ctx, s.ListPage, defaultListPageSize, ip, hostname)
}

func findByIPAndHostname(ctx context.Context, list pageLister, pageSize int, ip, hostname string) (*domain.HostEntry, error) {
	var cursor ulid.ULID
	for {
		page, next, done, err := list(ctx, cursor, pageSize)
		if err != nil {
			return nil, err
		}
		for i := range page {
			if page[i].IP == ip && page[i].Hostname == hostname {
				return &page[i], nil
			}
		}
		if done {
			return nil, domain.ErrNotFound("host", fmt.Sprintf("%s/%s", ip, hostname))
		}
		cursor = next
	}
}

// Search filters host entries using the provided search filter. Streams
// ListPage pages rather than draining the whole inventory first (D-04): its
// peak is bounded by the result-set size plus one page rather than by the
// whole inventory. Ordering is preserved (D-10's ascending aggregate-ULID
// order) because entries are appended in the order pages arrive.
func (s *Storage) Search(ctx context.Context, filter domain.SearchFilter) ([]domain.HostEntry, error) {
	var results []domain.HostEntry
	var cursor ulid.ULID
	for {
		page, next, done, err := s.ListPage(ctx, cursor, defaultListPageSize)
		if err != nil {
			return nil, err
		}
		for _, entry := range page {
			if filter.IsEmpty() || matchesFilter(entry, filter) {
				results = append(results, entry)
			}
		}
		if done {
			return results, nil
		}
		cursor = next
	}
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
	if err != nil {
		return nil, oops.Wrapf(err, "get hosts at time %s", at.Format(time.RFC3339))
	}
	return entries, nil
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

		case domain.HostCompacted:
			entry = &domain.HostEntry{
				ID:        aggregateID,
				IP:        ev.IPAddress,
				Hostname:  ev.Hostname,
				Aliases:   ev.Aliases,
				Comment:   ev.Comment,
				Tags:      ev.Tags,
				CreatedAt: ev.CreatedAt,
				UpdatedAt: ev.UpdatedAt,
				Version:   env.Version,
				Deleted:   ev.Deleted,
			}

		case domain.SnapshotCreated, domain.SnapshotRolledBack, domain.SnapshotDeleted:
			// Snapshot events are valid but not relevant to host projection.
			continue

		default:
			return nil, oops.Errorf("unknown event type %q for aggregate %s", env.Event.Type, aggregateID)
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

// getAggregateIDPage returns up to limit distinct aggregate IDs strictly
// greater than after, in ascending order — the keyset query behind
// ListPage. Served by the existing idx_events_aggregate(aggregate_id,
// event_version) covering index (migrations/001_initial.sql); no new index,
// no migration.
func getAggregateIDPage(conn *sqlite.Conn, after ulid.ULID, limit int) ([]ulid.ULID, error) {
	var ids []ulid.ULID
	err := sqlitex.Execute(conn,
		`SELECT DISTINCT aggregate_id FROM events
		 WHERE aggregate_id > ? ORDER BY aggregate_id LIMIT ?`,
		&sqlitex.ExecOptions{
			Args: []any{after.String(), limit},
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
		return nil, oops.Wrapf(err, "get aggregate id page after %s", after)
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
