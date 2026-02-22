package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
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
	handler   *CommandHandler
	store     storage.Storage
	hostsGen  *HostsFileGenerator
	hooks     *HookExecutor
	startTime time.Time
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

// NewHostsServiceImpl creates a new service backed by the given CommandHandler.
func NewHostsServiceImpl(handler *CommandHandler, store storage.Storage, opts ...ServiceOption) *HostsServiceImpl {
	svc := &HostsServiceImpl{
		handler:   handler,
		store:     store,
		startTime: time.Now(),
	}
	for _, opt := range opts {
		opt(svc)
	}
	return svc
}

// mapError converts oops-coded domain errors to gRPC status errors.
func mapError(err error) error {
	if oopsErr, ok := oops.AsOops(err); ok {
		code, _ := oopsErr.Code().(string)
		return status.Error(domain.GRPCCode(code), oopsErr.Error())
	}
	return status.Error(codes.Internal, err.Error())
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
		Version:   entry.Version,
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

	var expectedVersion string
	if req.ExpectedVersion != nil {
		expectedVersion = *req.ExpectedVersion
	}

	entry, err := s.handler.UpdateHost(ctx, id, ip, hostname, comment, tags, aliases, expectedVersion)
	if err != nil {
		return nil, mapError(err)
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

	// Load the entry to get current version since proto DeleteHostRequest
	// lacks expected_version. This is an extra read but CommandHandler.DeleteHost
	// also validates the entry exists, so it's safe (just a minor inefficiency).
	entry, getErr := s.handler.GetHost(ctx, id)
	if getErr != nil {
		return nil, mapError(getErr)
	}

	if err := s.handler.DeleteHost(ctx, id, entry.Version); err != nil {
		return nil, mapError(err)
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
	filter := domain.SearchFilter{
		Query: &query,
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

// ImportHosts implements the bidi-streaming import RPC.
func (s *HostsServiceImpl) ImportHosts(stream grpc.BidiStreamingServer[hostsv1.ImportHostsRequest, hostsv1.ImportHostsResponse]) error {
	ctx := stream.Context()

	// Accumulate chunks
	var buf bytes.Buffer
	var format, conflictMode string

	for {
		req, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		buf.Write(req.GetChunk())

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
		errMsg := fmt.Sprintf("format %q not yet supported; only \"hosts\" is implemented", format)
		return stream.Send(&hostsv1.ImportHostsResponse{Error: &errMsg})
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
			// Check if it's a duplicate
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
					if findErr != nil || existing == nil {
						stats.Failed++
						stats.ValidationErrors = append(stats.ValidationErrors,
							fmt.Sprintf("Entry %d: failed to find existing entry for replace: %v", i+1, findErr))
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
					// Send final stats and abort
					return stream.Send(&stats)
				}
			} else {
				stats.Failed++
				stats.ValidationErrors = append(stats.ValidationErrors,
					fmt.Sprintf("Entry %d: %v", i+1, addErr))
			}
		}

		// Send progress every 10 entries
		if stats.Processed%10 == 0 {
			if err := stream.Send(&stats); err != nil {
				return err
			}
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
		gen := s.hostsGen
		if gen == nil {
			gen = NewHostsFileGenerator("/dev/null")
		}
		data = []byte(gen.FormatHostsFile(entries))

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
		_ = w.Write([]string{"id", "ip_address", "hostname", "comment", "tags", "aliases"})
		for _, e := range entries {
			comment := ""
			if e.Comment != nil {
				comment = *e.Comment
			}
			_ = w.Write([]string{
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
