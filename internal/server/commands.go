package server

import (
	"context"
	"crypto/rand"
	"fmt"
	"strconv"
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
	entropy *ulid.MonotonicEntropy
}

// NewCommandHandler creates a command handler backed by the given storage.
func NewCommandHandler(store storage.Storage) *CommandHandler {
	return &CommandHandler{
		store:   store,
		entropy: ulid.Monotonic(rand.Reader, 0),
	}
}

// newID generates a new ULID.
func (h *CommandHandler) newID() ulid.ULID {
	return ulid.MustNew(ulid.Timestamp(time.Now()), h.entropy)
}

// nextVersion returns the next integer version string given the current one.
// An empty current version yields "1".
func nextVersion(current string) string {
	if current == "" {
		return "1"
	}
	n, err := strconv.Atoi(current)
	if err != nil {
		return "1"
	}
	return strconv.Itoa(n + 1)
}

// AddHost creates a new host entry after validating inputs and checking for duplicates.
func (h *CommandHandler) AddHost(
	ctx context.Context,
	ip, hostname string,
	comment *string,
	tags, aliases []string,
) (*domain.HostEntry, error) {
	// Validate inputs
	if err := validation.ValidateIPAddress(ip); err != nil {
		return nil, err
	}
	if err := validation.ValidateHostname(hostname); err != nil {
		return nil, err
	}
	if errs := validation.ValidateAliases(aliases, hostname); len(errs) > 0 {
		return nil, domain.ErrValidationf("alias validation: %v", errs[0])
	}

	// Check for duplicate — FindByIPAndHostname returns ErrNotFound when
	// no match exists, which is the expected (non-duplicate) case.
	existing, err := h.store.FindByIPAndHostname(ctx, ip, hostname)
	if err == nil && existing != nil {
		return nil, domain.ErrDuplicate(ip, hostname)
	}
	// If the error is not_found, that's fine (no duplicate).
	// Any other error is a real storage problem.
	if err != nil {
		if oopsErr, ok := oops.AsOops(err); !ok || oopsErr.Code() != domain.CodeNotFound {
			return nil, domain.ErrStorage(err)
		}
	}

	// Generate ID and create event
	id := h.newID()
	now := time.Now().UTC()

	if tags == nil {
		tags = []string{}
	}
	if aliases == nil {
		aliases = []string{}
	}

	hostEvent, err := domain.NewHostEvent(domain.HostCreated{
		IPAddress: ip,
		Hostname:  hostname,
		Aliases:   aliases,
		Comment:   comment,
		Tags:      tags,
		CreatedAt: now,
	})
	if err != nil {
		return nil, domain.ErrInternal(err)
	}

	version := "1"
	env := domain.EventEnvelope{
		EventID:     h.newID(),
		AggregateID: id,
		Event:       hostEvent,
		Version:     version,
		CreatedAt:   now,
	}

	if err := h.store.AppendEvent(ctx, id, env, ""); err != nil {
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
func (h *CommandHandler) UpdateHost(
	ctx context.Context,
	id ulid.ULID,
	ip, hostname *string,
	comment **string,
	tags, aliases *[]string,
	expectedVersion string,
) (*domain.HostEntry, error) {
	// Load and replay events to get current state
	current, err := h.store.GetByID(ctx, id)
	if err != nil {
		return nil, domain.ErrStorage(err)
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
		he, err := domain.NewHostEvent(domain.IPAddressChanged{
			OldIP:     current.IP,
			NewIP:     *ip,
			ChangedAt: now,
		})
		if err != nil {
			return nil, domain.ErrInternal(err)
		}
		curVersion = nextVersion(curVersion)
		events = append(events, domain.EventEnvelope{
			EventID:     h.newID(),
			AggregateID: id,
			Event:       he,
			Version:     curVersion,
			CreatedAt:   now,
		})
		current.IP = *ip
	}

	// Hostname change
	if hostname != nil && *hostname != current.Hostname {
		if err := validation.ValidateHostname(*hostname); err != nil {
			return nil, err
		}
		he, err := domain.NewHostEvent(domain.HostnameChanged{
			OldHostname: current.Hostname,
			NewHostname: *hostname,
			ChangedAt:   now,
		})
		if err != nil {
			return nil, domain.ErrInternal(err)
		}
		curVersion = nextVersion(curVersion)
		events = append(events, domain.EventEnvelope{
			EventID:     h.newID(),
			AggregateID: id,
			Event:       he,
			Version:     curVersion,
			CreatedAt:   now,
		})
		current.Hostname = *hostname
	}

	// Comment change
	if comment != nil {
		he, err := domain.NewHostEvent(domain.CommentUpdated{
			OldComment: current.Comment,
			NewComment: *comment,
			UpdatedAt:  now,
		})
		if err != nil {
			return nil, domain.ErrInternal(err)
		}
		curVersion = nextVersion(curVersion)
		events = append(events, domain.EventEnvelope{
			EventID:     h.newID(),
			AggregateID: id,
			Event:       he,
			Version:     curVersion,
			CreatedAt:   now,
		})
		current.Comment = *comment
	}

	// Tags change
	if tags != nil {
		he, err := domain.NewHostEvent(domain.TagsModified{
			OldTags:    current.Tags,
			NewTags:    *tags,
			ModifiedAt: now,
		})
		if err != nil {
			return nil, domain.ErrInternal(err)
		}
		curVersion = nextVersion(curVersion)
		events = append(events, domain.EventEnvelope{
			EventID:     h.newID(),
			AggregateID: id,
			Event:       he,
			Version:     curVersion,
			CreatedAt:   now,
		})
		current.Tags = *tags
	}

	// Aliases change
	if aliases != nil {
		// Use the potentially-updated hostname for alias validation
		if errs := validation.ValidateAliases(*aliases, current.Hostname); len(errs) > 0 {
			return nil, domain.ErrValidationf("alias validation: %v", errs[0])
		}
		he, err := domain.NewHostEvent(domain.AliasesModified{
			OldAliases: current.Aliases,
			NewAliases: *aliases,
			ModifiedAt: now,
		})
		if err != nil {
			return nil, domain.ErrInternal(err)
		}
		curVersion = nextVersion(curVersion)
		events = append(events, domain.EventEnvelope{
			EventID:     h.newID(),
			AggregateID: id,
			Event:       he,
			Version:     curVersion,
			CreatedAt:   now,
		})
		current.Aliases = *aliases
	}

	if len(events) == 0 {
		return current, nil
	}

	if err := h.store.AppendEvents(ctx, id, events, expectedVersion); err != nil {
		return nil, err
	}

	current.Version = curVersion
	current.UpdatedAt = now
	return current, nil
}

// DeleteHost soft-deletes a host by appending a HostDeleted event.
func (h *CommandHandler) DeleteHost(
	ctx context.Context,
	id ulid.ULID,
	expectedVersion string,
) error {
	current, err := h.store.GetByID(ctx, id)
	if err != nil {
		return domain.ErrStorage(err)
	}
	if current == nil {
		return domain.ErrNotFound("host", id.String())
	}
	if current.Deleted {
		return domain.ErrNotFound("host", id.String())
	}

	now := time.Now().UTC()
	he, err := domain.NewHostEvent(domain.HostDeleted{
		IPAddress: current.IP,
		Hostname:  current.Hostname,
		DeletedAt: now,
	})
	if err != nil {
		return domain.ErrInternal(err)
	}

	newVersion := nextVersion(current.Version)
	env := domain.EventEnvelope{
		EventID:     h.newID(),
		AggregateID: id,
		Event:       he,
		Version:     newVersion,
		CreatedAt:   now,
	}

	return h.store.AppendEvent(ctx, id, env, expectedVersion)
}

// GetHost retrieves a single host entry by ID.
func (h *CommandHandler) GetHost(ctx context.Context, id ulid.ULID) (*domain.HostEntry, error) {
	entry, err := h.store.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get host: %w", err)
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
		return nil, fmt.Errorf("list hosts: %w", err)
	}
	return entries, nil
}

// SearchHosts finds host entries matching the given filter criteria.
func (h *CommandHandler) SearchHosts(ctx context.Context, filter domain.SearchFilter) ([]domain.HostEntry, error) {
	entries, err := h.store.Search(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("search hosts: %w", err)
	}
	return entries, nil
}
