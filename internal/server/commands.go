package server

import (
	"context"
	"crypto/rand"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/samber/oops"

	"github.com/fzymgc-house/router-hosts/internal/domain"
	"github.com/fzymgc-house/router-hosts/internal/storage"
	"github.com/fzymgc-house/router-hosts/internal/validation"
)

// CommandHandler implements domain logic for host CRUD operations
// using event sourcing with the storage layer.
type CommandHandler struct {
	store   storage.Storage
	queue   *WriteQueue // serializes write operations; nil means direct writes
	entropy *ulid.MonotonicEntropy
	mu      sync.Mutex // protects entropy
}

// NewCommandHandler creates a command handler backed by the given storage.
// Write operations are performed directly on the storage layer.
// Use NewCommandHandlerWithQueue to route writes through a serializing queue.
func NewCommandHandler(store storage.Storage) *CommandHandler {
	return &CommandHandler{
		store:   store,
		entropy: ulid.Monotonic(rand.Reader, 0),
	}
}

// NewCommandHandlerWithQueue creates a command handler that routes all write
// operations (AddHost, UpdateHost, DeleteHost) through the provided WriteQueue,
// serializing concurrent writes at the application level.
func NewCommandHandlerWithQueue(store storage.Storage, queue *WriteQueue) *CommandHandler {
	return &CommandHandler{
		store:   store,
		queue:   queue,
		entropy: ulid.Monotonic(rand.Reader, 0),
	}
}

// submitWrite executes fn either through the write queue (if configured) or
// directly. Read-path callers must not use this helper.
func (h *CommandHandler) submitWrite(ctx context.Context, fn func() error) error {
	if h.queue != nil {
		return h.queue.Submit(ctx, fn)
	}
	return fn()
}

// newID generates a new ULID. Safe for concurrent use.
func (h *CommandHandler) newID() ulid.ULID {
	h.mu.Lock()
	defer h.mu.Unlock()
	return ulid.MustNew(ulid.Timestamp(time.Now()), h.entropy)
}

// nextVersion returns the next sequential version given the current one.
// A zero current version yields 1.
func nextVersion(current int64) int64 {
	return current + 1
}

// newEnvelope creates an EventEnvelope for the given aggregate and domain event.
// It wraps domain.NewHostEvent, assigns a fresh event ID, and stamps CreatedAt.
func (h *CommandHandler) newEnvelope(aggregateID ulid.ULID, version int64, event any) (domain.EventEnvelope, error) {
	he, err := domain.NewHostEvent(event)
	if err != nil {
		return domain.EventEnvelope{}, domain.ErrInternal(err)
	}
	return domain.EventEnvelope{
		EventID:     h.newID(),
		AggregateID: aggregateID,
		Event:       he,
		Version:     version,
		CreatedAt:   time.Now().UTC(),
	}, nil
}

// AddHost creates a new host entry after validating inputs and checking for duplicates.
// The duplicate check and the event append execute atomically inside submitWrite so that
// two concurrent AddHost calls with the same IP+hostname cannot both pass the check.
func (h *CommandHandler) AddHost(
	ctx context.Context,
	ip, hostname string,
	comment *string,
	tags, aliases []string,
) (*domain.HostEntry, error) {
	// Validate inputs outside the write-queue closure — these are pure checks
	// that do not touch storage and need not be serialized.
	if err := validation.ValidateIPAddress(ip); err != nil {
		return nil, err
	}
	if err := validation.ValidateHostname(hostname); err != nil {
		return nil, err
	}
	if errs := validation.ValidateAliases(aliases, hostname); len(errs) > 0 {
		return nil, domain.ErrValidationf("alias validation: %v", errs[0])
	}

	if tags == nil {
		tags = []string{}
	}
	if aliases == nil {
		aliases = []string{}
	}

	// Generate the aggregate ID before entering the queue so the returned
	// HostEntry is available regardless of which code path resolves the closure.
	id := h.newID()
	now := time.Now().UTC()
	const version int64 = 1

	env, err := h.newEnvelope(id, version, domain.HostCreated{
		IPAddress: ip,
		Hostname:  hostname,
		Aliases:   aliases,
		Comment:   comment,
		Tags:      tags,
		CreatedAt: now,
	})
	if err != nil {
		return nil, err
	}

	// The duplicate check and the storage write are performed inside submitWrite
	// so they execute while holding the write-queue serialization lock.  This
	// prevents two concurrent AddHost calls with the same IP+hostname from both
	// passing the check and creating duplicate entries.
	if err := h.submitWrite(ctx, func() error {
		// Check for duplicate — FindByIPAndHostname returns ErrNotFound when
		// no match exists, which is the expected (non-duplicate) case.
		existing, findErr := h.store.FindByIPAndHostname(ctx, ip, hostname)
		if findErr == nil && existing != nil {
			return domain.ErrDuplicate(ip, hostname)
		}
		// If the error is not_found, that's fine (no duplicate).
		// Any other error is a real storage problem.
		if findErr != nil {
			if oopsErr, ok := oops.AsOops(findErr); !ok || oopsErr.Code() != domain.CodeNotFound {
				return domain.ErrStorage(findErr)
			}
		}

		return h.store.AppendEvent(ctx, id, env, 0)
	}); err != nil {
		return nil, err
	}

	return &domain.HostEntry{
		ID:        id,
		IP:        ip,
		Hostname:  hostname,
		Aliases:   aliases,
		Comment:   comment,
		Tags:      tags,
		Version:   version,
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

// UpdateHost applies granular changes to an existing host entry with optimistic concurrency.
// Double-pointer semantics for comment: nil outer pointer means "don't change"; non-nil outer
// pointer with nil inner pointer means "clear the comment"; non-nil inner pointer means "set to that value".
func (h *CommandHandler) UpdateHost(
	ctx context.Context,
	id ulid.ULID,
	ip, hostname *string,
	comment **string,
	tags, aliases *[]string,
	expectedVersion int64,
) (*domain.HostEntry, error) {
	// Load current state from projection
	current, err := h.store.GetByID(ctx, id)
	if err != nil {
		return nil, oops.Wrapf(err, "update host")
	}
	if current == nil {
		return nil, domain.ErrNotFound("host", id.String())
	}
	if current.Deleted {
		return nil, domain.ErrNotFound("host", id.String())
	}

	now := time.Now().UTC()
	curVersion := current.Version
	var events []domain.EventEnvelope

	// IP change
	if ip != nil && *ip != current.IP {
		if err := validation.ValidateIPAddress(*ip); err != nil {
			return nil, err
		}
		curVersion = nextVersion(curVersion)
		env, err := h.newEnvelope(id, curVersion, domain.IPAddressChanged{
			OldIP:     current.IP,
			NewIP:     *ip,
			ChangedAt: now,
		})
		if err != nil {
			return nil, err
		}
		events = append(events, env)
		current.IP = *ip
	}

	// Hostname change
	if hostname != nil && *hostname != current.Hostname {
		if err := validation.ValidateHostname(*hostname); err != nil {
			return nil, err
		}
		curVersion = nextVersion(curVersion)
		env, err := h.newEnvelope(id, curVersion, domain.HostnameChanged{
			OldHostname: current.Hostname,
			NewHostname: *hostname,
			ChangedAt:   now,
		})
		if err != nil {
			return nil, err
		}
		events = append(events, env)
		current.Hostname = *hostname
	}

	// Comment change
	if comment != nil {
		curVersion = nextVersion(curVersion)
		env, err := h.newEnvelope(id, curVersion, domain.CommentUpdated{
			OldComment: current.Comment,
			NewComment: *comment,
			UpdatedAt:  now,
		})
		if err != nil {
			return nil, err
		}
		events = append(events, env)
		current.Comment = *comment
	}

	// Tags change
	if tags != nil {
		curVersion = nextVersion(curVersion)
		env, err := h.newEnvelope(id, curVersion, domain.TagsModified{
			OldTags:    current.Tags,
			NewTags:    *tags,
			ModifiedAt: now,
		})
		if err != nil {
			return nil, err
		}
		events = append(events, env)
		current.Tags = *tags
	}

	// Aliases change
	if aliases != nil {
		// Use the potentially-updated hostname for alias validation
		if errs := validation.ValidateAliases(*aliases, current.Hostname); len(errs) > 0 {
			return nil, domain.ErrValidationf("alias validation: %v", errs[0])
		}
		curVersion = nextVersion(curVersion)
		env, err := h.newEnvelope(id, curVersion, domain.AliasesModified{
			OldAliases: current.Aliases,
			NewAliases: *aliases,
			ModifiedAt: now,
		})
		if err != nil {
			return nil, err
		}
		events = append(events, env)
		current.Aliases = *aliases
	}

	if len(events) == 0 {
		return current, nil
	}

	if err := h.submitWrite(ctx, func() error {
		return h.store.AppendEvents(ctx, id, events, expectedVersion)
	}); err != nil {
		return nil, err
	}

	current.Version = curVersion
	current.UpdatedAt = now
	return current, nil
}

// DeleteHost soft-deletes a host by appending a HostDeleted event.
// It uses optimistic concurrency control: it checks the current version and compares it against
// expectedVersion when appending the delete event to prevent concurrent modification conflicts.
func (h *CommandHandler) DeleteHost(
	ctx context.Context,
	id ulid.ULID,
	expectedVersion int64,
) error {
	current, err := h.store.GetByID(ctx, id)
	if err != nil {
		return oops.Wrapf(err, "delete host")
	}
	if current == nil {
		return domain.ErrNotFound("host", id.String())
	}
	if current.Deleted {
		return domain.ErrNotFound("host", id.String())
	}

	now := time.Now().UTC()
	newVersion := nextVersion(current.Version)
	env, err := h.newEnvelope(id, newVersion, domain.HostDeleted{
		IPAddress: current.IP,
		Hostname:  current.Hostname,
		DeletedAt: now,
	})
	if err != nil {
		return err
	}

	return h.submitWrite(ctx, func() error {
		return h.store.AppendEvent(ctx, id, env, expectedVersion)
	})
}

// PrepareDeleteEvent builds the AggregateEvents for a soft-delete without
// persisting anything. The caller is responsible for writing the events.
func (h *CommandHandler) PrepareDeleteEvent(ctx context.Context, entry *domain.HostEntry) (storage.AggregateEvents, error) {
	now := time.Now().UTC()
	newVersion := nextVersion(entry.Version)
	env, err := h.newEnvelope(entry.ID, newVersion, domain.HostDeleted{
		IPAddress: entry.IP,
		Hostname:  entry.Hostname,
		DeletedAt: now,
	})
	if err != nil {
		return storage.AggregateEvents{}, err
	}

	return storage.AggregateEvents{
		AggregateID:     entry.ID,
		Events:          []domain.EventEnvelope{env},
		ExpectedVersion: entry.Version,
	}, nil
}

// PrepareAddEvent builds the AggregateEvents for creating a new host without
// persisting anything. The caller is responsible for writing the events.
// It does NOT check for duplicates — callers must ensure the state is clean.
func (h *CommandHandler) PrepareAddEvent(
	ip, hostname string,
	comment *string,
	tags, aliases []string,
) (storage.AggregateEvents, *domain.HostEntry, error) {
	if err := validation.ValidateIPAddress(ip); err != nil {
		return storage.AggregateEvents{}, nil, err
	}
	if err := validation.ValidateHostname(hostname); err != nil {
		return storage.AggregateEvents{}, nil, err
	}
	if errs := validation.ValidateAliases(aliases, hostname); len(errs) > 0 {
		return storage.AggregateEvents{}, nil, domain.ErrValidationf("alias validation: %v", errs[0])
	}

	if tags == nil {
		tags = []string{}
	}
	if aliases == nil {
		aliases = []string{}
	}

	id := h.newID()
	now := time.Now().UTC()

	const version int64 = 1
	env, err := h.newEnvelope(id, version, domain.HostCreated{
		IPAddress: ip,
		Hostname:  hostname,
		Aliases:   aliases,
		Comment:   comment,
		Tags:      tags,
		CreatedAt: now,
	})
	if err != nil {
		return storage.AggregateEvents{}, nil, err
	}

	entry := &domain.HostEntry{
		ID:        id,
		IP:        ip,
		Hostname:  hostname,
		Aliases:   aliases,
		Comment:   comment,
		Tags:      tags,
		Version:   version,
		CreatedAt: now,
		UpdatedAt: now,
	}

	return storage.AggregateEvents{
		AggregateID:     id,
		Events:          []domain.EventEnvelope{env},
		ExpectedVersion: 0,
	}, entry, nil
}

// GetHost retrieves a single host entry by ID.
func (h *CommandHandler) GetHost(ctx context.Context, id ulid.ULID) (*domain.HostEntry, error) {
	entry, err := h.store.GetByID(ctx, id)
	if err != nil {
		return nil, oops.Wrapf(err, "get host")
	}
	if entry == nil || entry.Deleted {
		return nil, domain.ErrNotFound("host", id.String())
	}
	return entry, nil
}

// ListHosts returns all non-deleted host entries.
func (h *CommandHandler) ListHosts(ctx context.Context) ([]domain.HostEntry, error) {
	entries, err := h.store.ListAll(ctx)
	if err != nil {
		return nil, oops.Wrapf(err, "list hosts")
	}
	return entries, nil
}

// SearchHosts finds host entries matching the given filter criteria.
func (h *CommandHandler) SearchHosts(ctx context.Context, filter domain.SearchFilter) ([]domain.HostEntry, error) {
	entries, err := h.store.Search(ctx, filter)
	if err != nil {
		return nil, oops.Wrapf(err, "search hosts")
	}
	return entries, nil
}
