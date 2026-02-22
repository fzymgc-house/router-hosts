package server

import (
	"context"

	"github.com/oklog/ulid/v2"
	"github.com/samber/oops"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
	"github.com/fzymgc-house/router-hosts/internal/domain"
)

// HostsServiceImpl implements the gRPC HostsService CRUD methods.
type HostsServiceImpl struct {
	hostsv1.UnimplementedHostsServiceServer
	handler *CommandHandler
}

// NewHostsServiceImpl creates a new service backed by the given CommandHandler.
func NewHostsServiceImpl(handler *CommandHandler) *HostsServiceImpl {
	return &HostsServiceImpl{handler: handler}
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
