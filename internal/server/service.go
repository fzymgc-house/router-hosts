package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/samber/oops"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
	"github.com/fzymgc-house/router-hosts/internal/domain"
	"github.com/fzymgc-house/router-hosts/internal/storage"
)

// HostsServiceImpl implements the gRPC HostsService methods.
type HostsServiceImpl struct {
	hostsv1.UnimplementedHostsServiceServer
	handler           *CommandHandler
	store             storage.Storage
	hostsGen          *HostsFileGenerator
	hooks             *HookExecutor
	startTime         time.Time
	retentionMaxSnaps *int
	retentionMaxAge   *int
	version           string
	buildInfo         string
}

// ServiceOption configures optional dependencies on HostsServiceImpl.
type ServiceOption func(*HostsServiceImpl)

// WithHostsGenerator sets the hosts file generator.
func WithHostsGenerator(gen *HostsFileGenerator) ServiceOption {
	return func(s *HostsServiceImpl) { s.hostsGen = gen }
}

// WithHookExecutor sets the hook executor.
func WithHookExecutor(hooks *HookExecutor) ServiceOption {
	return func(s *HostsServiceImpl) { s.hooks = hooks }
}

// WithVersion sets the version and build info strings returned by the Health RPC.
func WithVersion(version, buildInfo string) ServiceOption {
	return func(s *HostsServiceImpl) {
		s.version = version
		s.buildInfo = buildInfo
	}
}

// WithRetentionConfig sets the snapshot retention policy applied after each
// CreateSnapshot call. Pass nil for either parameter to use the storage default.
func WithRetentionConfig(maxSnapshots *int, maxAgeDays *int) ServiceOption {
	return func(s *HostsServiceImpl) {
		s.retentionMaxSnaps = maxSnapshots
		s.retentionMaxAge = maxAgeDays
	}
}

// NewHostsServiceImpl creates a new service backed by the given CommandHandler.
func NewHostsServiceImpl(handler *CommandHandler, store storage.Storage, opts ...ServiceOption) *HostsServiceImpl {
	svc := &HostsServiceImpl{
		handler:   handler,
		store:     store,
		startTime: time.Now(),
		version:   "dev",
		buildInfo: "dev",
	}
	for _, opt := range opts {
		opt(svc)
	}
	return svc
}

// mapError converts oops-coded domain errors to gRPC status errors.
// For codes.Internal, the detailed error message is not forwarded to the
// client to avoid leaking internal state; it is logged server-side here.
func mapError(err error) error {
	if oopsErr, ok := oops.AsOops(err); ok {
		code, _ := oopsErr.Code().(string)
		grpcCode := domain.GRPCCode(code)
		if grpcCode == codes.Internal {
			slog.Error("internal server error", "error", oopsErr)
			return status.Error(codes.Internal, "internal server error")
		}
		return status.Error(grpcCode, oopsErr.Error())
	}
	slog.Error("internal server error", "error", err)
	return status.Error(codes.Internal, "internal server error")
}

// domainToProto converts a domain.HostEntry to the proto HostEntry.
func domainToProto(entry *domain.HostEntry) *hostsv1.HostEntry {
	pb := &hostsv1.HostEntry{
		Id:        entry.ID.String(),
		IpAddress: entry.IP,
		Hostname:  entry.Hostname,
		Comment:   entry.Comment,
		Tags:      entry.Tags,
		CreatedAt: timestamppb.New(entry.CreatedAt),
		UpdatedAt: timestamppb.New(entry.UpdatedAt),
		Version:   strconv.FormatInt(entry.Version, 10),
		Aliases:   entry.Aliases,
	}
	return pb
}

// AddHost creates a new host entry.
func (s *HostsServiceImpl) AddHost(ctx context.Context, req *hostsv1.AddHostRequest) (*hostsv1.AddHostResponse, error) {
	entry, err := s.handler.AddHost(ctx, req.GetIpAddress(), req.GetHostname(), req.Comment, req.GetTags(), req.GetAliases())
	if err != nil {
		return nil, mapError(err)
	}
	if s.hostsGen != nil {
		if _, regenErr := s.hostsGen.Regenerate(ctx, s.store); regenErr != nil {
			slog.Error("hosts file regeneration failed after AddHost", "error", regenErr)
		}
	}
	return &hostsv1.AddHostResponse{
		Id:    entry.ID.String(),
		Entry: domainToProto(entry),
	}, nil
}

// GetHost retrieves a host entry by ID.
func (s *HostsServiceImpl) GetHost(ctx context.Context, req *hostsv1.GetHostRequest) (*hostsv1.GetHostResponse, error) {
	id, err := ulid.Parse(req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid ID %q: %v", req.GetId(), err)
	}
	entry, err := s.handler.GetHost(ctx, id)
	if err != nil {
		return nil, mapError(err)
	}
	return &hostsv1.GetHostResponse{
		Entry: domainToProto(entry),
	}, nil
}

// UpdateHost applies changes to an existing host entry.
func (s *HostsServiceImpl) UpdateHost(ctx context.Context, req *hostsv1.UpdateHostRequest) (*hostsv1.UpdateHostResponse, error) {
	id, err := ulid.Parse(req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid ID %q: %v", req.GetId(), err)
	}

	// Map proto optional fields to Go pointer semantics
	var ip, hostname *string
	if req.IpAddress != nil {
		ip = req.IpAddress
	}
	if req.Hostname != nil {
		hostname = req.Hostname
	}

	// Comment: proto *string maps to **string for CommandHandler
	var comment **string
	if req.Comment != nil {
		comment = &req.Comment
	}

	// Aliases/Tags: wrapper messages for optional semantics
	var aliases, tags *[]string
	if req.Aliases != nil {
		v := req.Aliases.GetValues()
		if v == nil {
			v = []string{}
		}
		aliases = &v
	}
	if req.Tags != nil {
		v := req.Tags.GetValues()
		if v == nil {
			v = []string{}
		}
		tags = &v
	}

	var expectedVersion int64
	if req.ExpectedVersion != nil {
		v, parseErr := strconv.ParseInt(*req.ExpectedVersion, 10, 64)
		if parseErr != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid expected_version %q: %v", *req.ExpectedVersion, parseErr)
		}
		expectedVersion = v
	}

	entry, err := s.handler.UpdateHost(ctx, id, ip, hostname, comment, tags, aliases, expectedVersion)
	if err != nil {
		return nil, mapError(err)
	}
	if s.hostsGen != nil {
		if _, regenErr := s.hostsGen.Regenerate(ctx, s.store); regenErr != nil {
			slog.Error("hosts file regeneration failed after UpdateHost", "error", regenErr)
		}
	}
	return &hostsv1.UpdateHostResponse{
		Entry: domainToProto(entry),
	}, nil
}

// DeleteHost removes a host entry by ID.
func (s *HostsServiceImpl) DeleteHost(ctx context.Context, req *hostsv1.DeleteHostRequest) (*hostsv1.DeleteHostResponse, error) {
	id, err := ulid.Parse(req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid ID %q: %v", req.GetId(), err)
	}

	var expectedVersion int64
	if req.ExpectedVersion != nil {
		v, parseErr := strconv.ParseInt(*req.ExpectedVersion, 10, 64)
		if parseErr != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid expected_version %q: %v", *req.ExpectedVersion, parseErr)
		}
		expectedVersion = v
	} else {
		// No expected_version provided: use -1 to signal unconditional delete
		// (skip optimistic concurrency check in the storage layer).
		expectedVersion = -1
	}

	if err := s.handler.DeleteHost(ctx, id, expectedVersion); err != nil {
		return nil, mapError(err)
	}
	if s.hostsGen != nil {
		if _, regenErr := s.hostsGen.Regenerate(ctx, s.store); regenErr != nil {
			slog.Error("hosts file regeneration failed after DeleteHost", "error", regenErr)
		}
	}
	return &hostsv1.DeleteHostResponse{Success: true}, nil
}

// ListHosts streams all host entries.
func (s *HostsServiceImpl) ListHosts(req *hostsv1.ListHostsRequest, stream grpc.ServerStreamingServer[hostsv1.ListHostsResponse]) error {
	entries, err := s.handler.ListHosts(stream.Context())
	if err != nil {
		return mapError(err)
	}
	for i := range entries {
		if err := stream.Send(&hostsv1.ListHostsResponse{
			Entry: domainToProto(&entries[i]),
		}); err != nil {
			return err
		}
	}
	return nil
}

// SearchHosts streams host entries matching the query.
func (s *HostsServiceImpl) SearchHosts(req *hostsv1.SearchHostsRequest, stream grpc.ServerStreamingServer[hostsv1.SearchHostsResponse]) error {
	query := req.GetQuery()
	filter := domain.SearchFilter{}
	if query != "" {
		filter.Query = &query
	}

	if err := filter.Validate(); err != nil {
		return mapError(err)
	}

	entries, err := s.handler.SearchHosts(stream.Context(), filter)
	if err != nil {
		return mapError(err)
	}
	for i := range entries {
		if err := stream.Send(&hostsv1.SearchHostsResponse{
			Entry: domainToProto(&entries[i]),
		}); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Import / Export RPCs
// ---------------------------------------------------------------------------

// parsedHostLine represents a single entry parsed from hosts-format data.
type parsedHostLine struct {
	IP       string
	Hostname string
	Aliases  []string
	Comment  *string
	Tags     []string
}

// tagBracketRe matches a trailing [tag1, tag2] in a comment.
var tagBracketRe = regexp.MustCompile(`\[([^\]]*)\]\s*$`)

// parseHostsFormat parses hosts(5)-format data into structured entries.
func parseHostsFormat(data []byte) ([]parsedHostLine, []string) {
	var entries []parsedHostLine
	var errors []string

	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split on inline comment
		var mainPart, commentPart string
		if idx := strings.Index(line, "#"); idx >= 0 {
			mainPart = strings.TrimSpace(line[:idx])
			commentPart = strings.TrimSpace(line[idx+1:])
		} else {
			mainPart = line
		}

		// Split main part into fields (IP hostname [aliases...])
		fields := strings.Fields(mainPart)
		if len(fields) < 2 {
			errors = append(errors, fmt.Sprintf("Line %d: expected at least IP and hostname", lineNum))
			continue
		}

		entry := parsedHostLine{
			IP:       fields[0],
			Hostname: fields[1],
		}
		if len(fields) > 2 {
			entry.Aliases = fields[2:]
		}

		// Parse comment and tags
		if commentPart != "" {
			if m := tagBracketRe.FindStringSubmatch(commentPart); m != nil {
				tagStr := strings.TrimSpace(m[1])
				if tagStr != "" {
					for _, t := range strings.Split(tagStr, ",") {
						t = strings.TrimSpace(t)
						if t != "" {
							entry.Tags = append(entry.Tags, t)
						}
					}
				}
				commentPart = strings.TrimSpace(commentPart[:tagBracketRe.FindStringIndex(commentPart)[0]])
			}
			if commentPart != "" {
				entry.Comment = &commentPart
			}
		}

		entries = append(entries, entry)
	}
	return entries, errors
}

const maxImportBytes = 64 * 1024 * 1024 // 64 MiB

// ImportHosts implements the bidi-streaming import RPC.
func (s *HostsServiceImpl) ImportHosts(stream grpc.BidiStreamingServer[hostsv1.ImportHostsRequest, hostsv1.ImportHostsResponse]) error {
	ctx := stream.Context()

	// Accumulate chunks
	var buf bytes.Buffer
	var format, conflictMode string

	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}

		_, _ = buf.Write(req.GetChunk()) // bytes.Buffer.Write never returns an error
		if buf.Len() > maxImportBytes {
			return status.Errorf(codes.ResourceExhausted, "import payload exceeds maximum size (%d bytes)", maxImportBytes)
		}

		// Capture settings from first message that sets them
		if format == "" && req.GetFormat() != "" {
			format = req.GetFormat()
		}
		if conflictMode == "" && req.GetConflictMode() != "" {
			conflictMode = req.GetConflictMode()
		}

		if req.GetLastChunk() {
			break
		}
	}

	// Defaults
	if format == "" {
		format = "hosts"
	}
	if conflictMode == "" {
		conflictMode = "skip"
	}

	// Only hosts format is supported for now
	if format != "hosts" {
		return status.Errorf(codes.InvalidArgument, "import format %q not yet supported; only \"hosts\" is implemented", format)
	}

	if conflictMode != "skip" && conflictMode != "replace" && conflictMode != "strict" {
		return status.Errorf(codes.InvalidArgument, "invalid conflict_mode %q", conflictMode)
	}

	entries, parseErrors := parseHostsFormat(buf.Bytes())

	var stats hostsv1.ImportHostsResponse
	stats.Failed = int32(len(parseErrors))
	stats.ValidationErrors = parseErrors

	for i, entry := range entries {
		stats.Processed++

		// Try to add the entry
		_, addErr := s.handler.AddHost(ctx, entry.IP, entry.Hostname, entry.Comment, entry.Tags, entry.Aliases)
		if addErr == nil {
			stats.Created++
		} else {
			// Extract error code to distinguish duplicates from other errors
			isDuplicate := false
			if oopsErr, ok := oops.AsOops(addErr); ok {
				if code, _ := oopsErr.Code().(string); code == domain.CodeDuplicate {
					isDuplicate = true
				}
			}

			if isDuplicate {
				switch conflictMode {
				case "skip":
					stats.Skipped++
				case "replace":
					// Find existing and update
					existing, findErr := s.store.FindByIPAndHostname(ctx, entry.IP, entry.Hostname)
					if findErr != nil {
						stats.Failed++
						stats.ValidationErrors = append(stats.ValidationErrors,
							fmt.Sprintf("Entry %d: storage error looking up existing entry: %v", i+1, findErr))
						continue
					}
					if existing == nil {
						stats.Failed++
						stats.ValidationErrors = append(stats.ValidationErrors,
							fmt.Sprintf("Entry %d: no existing entry found for %s -> %s", i+1, entry.IP, entry.Hostname))
						continue
					}
					comment := entry.Comment
					var commentPtr **string
					commentPtr = &comment
					tags := entry.Tags
					if tags == nil {
						tags = []string{}
					}
					aliases := entry.Aliases
					if aliases == nil {
						aliases = []string{}
					}
					_, updateErr := s.handler.UpdateHost(ctx, existing.ID, nil, nil, commentPtr, &tags, &aliases, existing.Version)
					if updateErr != nil {
						stats.Failed++
						stats.ValidationErrors = append(stats.ValidationErrors,
							fmt.Sprintf("Entry %d: update failed: %v", i+1, updateErr))
					} else {
						stats.Updated++
					}
				case "strict":
					errMsg := fmt.Sprintf("duplicate entry at position %d: %s -> %s", i+1, entry.IP, entry.Hostname)
					stats.Error = &errMsg
					stats.Failed++
					// Send final stats and abort with explicit error
					if err := stream.Send(&stats); err != nil {
						return err
					}
					return status.Errorf(codes.AlreadyExists, "import aborted: %s", errMsg)
				}
			} else {
				stats.Failed++
				stats.ValidationErrors = append(stats.ValidationErrors,
					fmt.Sprintf("Entry %d (%s -> %s): %v", i+1, entry.IP, entry.Hostname, addErr))
				slog.Error("import entry failed due to storage or infrastructure error",
					"entry_index", i+1,
					"ip", entry.IP,
					"hostname", entry.Hostname,
					"error", addErr,
				)
			}
		}

		// Send progress every 10 entries
		if stats.Processed%10 == 0 {
			if err := stream.Send(&stats); err != nil {
				return err
			}
		}
	}

	if stats.Failed > 0 {
		slog.Warn("import completed with failures",
			"processed", stats.Processed,
			"failed", stats.Failed,
			"created", stats.Created,
		)
	}

	if s.hostsGen != nil && (stats.Created > 0 || stats.Updated > 0) {
		if _, regenErr := s.hostsGen.Regenerate(ctx, s.store); regenErr != nil {
			slog.Error("hosts file regeneration failed after ImportHosts", "error", regenErr)
		}
	}

	// Send final stats
	return stream.Send(&stats)
}

// ExportHosts implements the server-streaming export RPC.
func (s *HostsServiceImpl) ExportHosts(req *hostsv1.ExportHostsRequest, stream grpc.ServerStreamingServer[hostsv1.ExportHostsResponse]) error {
	ctx := stream.Context()
	format := req.GetFormat()
	if format == "" {
		format = "hosts"
	}

	entries, err := s.store.ListAll(ctx)
	if err != nil {
		return mapError(err)
	}

	var data []byte

	switch format {
	case "hosts":
		if s.hostsGen != nil {
			data = []byte(s.hostsGen.FormatHostsFile(entries))
		} else {
			data = []byte((&HostsFileGenerator{}).FormatHostsFile(entries))
		}

	case "json":
		// Convert to proto-like structures for clean JSON
		type jsonEntry struct {
			ID        string   `json:"id"`
			IPAddress string   `json:"ip_address"`
			Hostname  string   `json:"hostname"`
			Comment   *string  `json:"comment,omitempty"`
			Tags      []string `json:"tags"`
			Aliases   []string `json:"aliases"`
		}
		out := make([]jsonEntry, len(entries))
		for i, e := range entries {
			out[i] = jsonEntry{
				ID:        e.ID.String(),
				IPAddress: e.IP,
				Hostname:  e.Hostname,
				Comment:   e.Comment,
				Tags:      e.Tags,
				Aliases:   e.Aliases,
			}
		}
		data, err = json.MarshalIndent(out, "", "  ")
		if err != nil {
			return status.Errorf(codes.Internal, "json marshal: %v", err)
		}

	case "csv":
		var csvBuf bytes.Buffer
		w := csv.NewWriter(&csvBuf)
		_ = w.Write([]string{"id", "ip_address", "hostname", "comment", "tags", "aliases"}) // csv.Writer buffers errors; checked via w.Error() after Flush
		for _, e := range entries {
			comment := ""
			if e.Comment != nil {
				comment = *e.Comment
			}
			_ = w.Write([]string{ // error buffered; checked via w.Error() after Flush
				e.ID.String(),
				e.IP,
				e.Hostname,
				comment,
				strings.Join(e.Tags, ";"),
				strings.Join(e.Aliases, ";"),
			})
		}
		w.Flush()
		if err := w.Error(); err != nil {
			return status.Errorf(codes.Internal, "csv write: %v", err)
		}
		data = csvBuf.Bytes()

	default:
		return status.Errorf(codes.InvalidArgument, "unsupported export format %q", format)
	}

	return stream.Send(&hostsv1.ExportHostsResponse{Chunk: data})
}

// ---------------------------------------------------------------------------
// Snapshot RPCs
// ---------------------------------------------------------------------------

// CreateSnapshot captures the current state of the hosts database.
func (s *HostsServiceImpl) CreateSnapshot(ctx context.Context, req *hostsv1.CreateSnapshotRequest) (*hostsv1.CreateSnapshotResponse, error) {
	entries, err := s.store.ListAll(ctx)
	if err != nil {
		return nil, mapError(err)
	}

	var content string
	if s.hostsGen != nil {
		content = s.hostsGen.FormatHostsFile(entries)
	} else {
		content = (&HostsFileGenerator{}).FormatHostsFile(entries)
	}

	trigger := req.GetTrigger()
	if trigger == "" {
		trigger = "manual"
	}

	snapshotID := ulid.Make()

	var name *string
	if req.GetName() != "" {
		n := req.GetName()
		name = &n
	}

	snap := domain.NewSnapshot(snapshotID, content, trigger, name, entries)

	if err := s.store.SaveSnapshot(ctx, *snap); err != nil {
		return nil, mapError(err)
	}

	// Best-effort retention policy using configured values (nil = storage default).
	if _, err := s.store.ApplyRetentionPolicy(ctx, s.retentionMaxSnaps, s.retentionMaxAge); err != nil {
		slog.Warn("retention policy failed", "error", err, "snapshot_id", snapshotID.String(), "max_snapshots", s.retentionMaxSnaps, "max_age_days", s.retentionMaxAge)
	}

	return &hostsv1.CreateSnapshotResponse{
		SnapshotId: snapshotID.String(),
		CreatedAt:  timestamppb.New(snap.CreatedAt),
		EntryCount: snap.EntryCount,
	}, nil
}

// ListSnapshots streams snapshot metadata.
func (s *HostsServiceImpl) ListSnapshots(req *hostsv1.ListSnapshotsRequest, stream grpc.ServerStreamingServer[hostsv1.ListSnapshotsResponse]) error {
	ctx := stream.Context()

	var limit, offset *uint32
	if req.GetLimit() > 0 {
		l := req.GetLimit()
		limit = &l
	}
	if req.GetOffset() > 0 {
		o := req.GetOffset()
		offset = &o
	}

	metas, err := s.store.ListSnapshots(ctx, limit, offset)
	if err != nil {
		return mapError(err)
	}

	for _, m := range metas {
		name := ""
		if m.Name != nil {
			name = *m.Name
		}
		if err := stream.Send(&hostsv1.ListSnapshotsResponse{
			Snapshot: &hostsv1.Snapshot{
				SnapshotId: m.SnapshotID.String(),
				CreatedAt:  timestamppb.New(m.CreatedAt),
				EntryCount: m.EntryCount,
				Trigger:    m.Trigger,
				Name:       name,
			},
		}); err != nil {
			return err
		}
	}
	return nil
}

// RollbackToSnapshot restores the hosts database to a snapshot state.
// All deletes and re-imports are committed as a single atomic batch; a failure
// at any point leaves the database unchanged.
//
// The entire operation (backup snapshot, list, batch build, and commit) runs
// inside the write queue to prevent concurrent writes from interleaving between
// the backup and the batch commit.
func (s *HostsServiceImpl) RollbackToSnapshot(ctx context.Context, req *hostsv1.RollbackToSnapshotRequest) (*hostsv1.RollbackToSnapshotResponse, error) {
	snapshotID, err := ulid.Parse(req.GetSnapshotId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid snapshot_id %q: %v", req.GetSnapshotId(), err)
	}

	var resp *hostsv1.RollbackToSnapshotResponse

	writeErr := s.handler.submitWrite(ctx, func() error {
		// Load the target snapshot
		target, err := s.store.GetSnapshot(ctx, snapshotID)
		if err != nil {
			return err
		}
		if target == nil {
			return domain.ErrNotFound("snapshot", req.GetSnapshotId())
		}

		// Create a pre-rollback backup snapshot of current state. Holding the
		// write lock ensures no concurrent write can change state between the
		// backup and the batch commit below.
		backupResp, err := s.CreateSnapshot(ctx, &hostsv1.CreateSnapshotRequest{
			Name:    "pre-rollback-backup",
			Trigger: "pre-rollback",
		})
		if err != nil {
			return oops.Code(domain.CodeInternal).Wrapf(err, "create pre-rollback backup")
		}

		// Load current entries to build delete events.
		currentEntries, err := s.store.ListAll(ctx)
		if err != nil {
			return err
		}

		// Build the entire batch of events (deletes + creates) without persisting.
		var batch []storage.AggregateEvents

		for i := range currentEntries {
			ag, prepErr := s.handler.PrepareDeleteEvent(ctx, &currentEntries[i])
			if prepErr != nil {
				return oops.Wrapf(prepErr, "rollback: prepare delete for %s", currentEntries[i].ID)
			}
			batch = append(batch, ag)
		}

		var restoredCount int32
		for _, entry := range target.Entries {
			ag, _, prepErr := s.handler.PrepareAddEvent(entry.IP, entry.Hostname, entry.Comment, entry.Tags, entry.Aliases)
			if prepErr != nil {
				return oops.Wrapf(prepErr, "rollback: prepare add for %s/%s", entry.IP, entry.Hostname)
			}
			batch = append(batch, ag)
			restoredCount++
		}

		// Commit all events in one atomic transaction. If this fails, nothing is
		// persisted and the database remains in its pre-rollback state.
		if len(batch) > 0 {
			if err := s.store.AppendEventsBatch(ctx, batch); err != nil {
				return oops.Wrapf(err, "rollback: atomic batch write")
			}
		}

		resp = &hostsv1.RollbackToSnapshotResponse{
			Success:            true,
			NewSnapshotId:      backupResp.GetSnapshotId(),
			RestoredEntryCount: restoredCount,
		}
		return nil
	})
	if writeErr != nil {
		return nil, mapError(writeErr)
	}
	if s.hostsGen != nil {
		if _, regenErr := s.hostsGen.Regenerate(ctx, s.store); regenErr != nil {
			slog.Error("hosts file regeneration failed after RollbackToSnapshot", "error", regenErr)
		}
	}
	return resp, nil
}

// DeleteSnapshot removes a snapshot by ID.
func (s *HostsServiceImpl) DeleteSnapshot(ctx context.Context, req *hostsv1.DeleteSnapshotRequest) (*hostsv1.DeleteSnapshotResponse, error) {
	snapshotID, err := ulid.Parse(req.GetSnapshotId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid snapshot_id %q: %v", req.GetSnapshotId(), err)
	}
	if err := s.store.DeleteSnapshot(ctx, snapshotID); err != nil {
		return nil, mapError(err)
	}
	return &hostsv1.DeleteSnapshotResponse{Success: true}, nil
}

// ---------------------------------------------------------------------------
// Health Check RPCs
// ---------------------------------------------------------------------------

// Liveness returns true if the process is alive (always true if responding).
func (s *HostsServiceImpl) Liveness(_ context.Context, _ *hostsv1.LivenessRequest) (*hostsv1.LivenessResponse, error) {
	return &hostsv1.LivenessResponse{Alive: true}, nil
}

// Readiness checks storage connectivity.
func (s *HostsServiceImpl) Readiness(ctx context.Context, _ *hostsv1.ReadinessRequest) (*hostsv1.ReadinessResponse, error) {
	resp := &hostsv1.ReadinessResponse{Ready: true}
	if healthErr := s.store.HealthCheck(ctx); healthErr != nil {
		resp.Ready = false
		resp.Reason = healthErr.Error()
	}
	return resp, nil
}

// Health returns detailed component health status.
func (s *HostsServiceImpl) Health(ctx context.Context, _ *hostsv1.HealthRequest) (*hostsv1.HealthResponse, error) {
	uptimeSecs := int64(time.Since(s.startTime).Seconds())

	// Database health check with latency measurement
	dbStart := time.Now()
	dbErr := s.store.HealthCheck(ctx)
	latencyMs := time.Since(dbStart).Milliseconds()

	dbHealth := &hostsv1.DatabaseHealth{
		Connected: dbErr == nil,
		Backend:   s.store.BackendName(),
		LatencyMs: latencyMs,
	}
	if dbErr != nil {
		dbHealth.Error = dbErr.Error()
	}

	// Hooks health
	hooksHealth := &hostsv1.HooksHealth{}
	if s.hooks != nil {
		hooksHealth.ConfiguredCount = int32(s.hooks.HookCount())
		hooksHealth.HookNames = s.hooks.HookNames()
	}

	return &hostsv1.HealthResponse{
		Healthy: dbErr == nil,
		Server: &hostsv1.ServerInfo{
			Version:       s.version,
			UptimeSeconds: uptimeSecs,
			BuildInfo:     s.buildInfo,
		},
		Database: dbHealth,
		Acme: &hostsv1.AcmeHealth{
			Enabled: false,
			Status:  "disabled",
		},
		Hooks: hooksHealth,
	}, nil
}
