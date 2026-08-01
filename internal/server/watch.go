package server

import (
	"errors"
	"io"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
	"github.com/fzymgc-house/router-hosts/internal/contract"
)

// TemplateContractVersion is the template data contract version this server
// advertises on every WatchHosts SnapshotComplete terminator. Defined in
// internal/contract and must not be redeclared here.
const TemplateContractVersion = contract.TemplateVersion

// WatchHosts implements the bidirectional streaming RPC that serves host
// entries plus a snapshot terminator to a consumer for client-side template
// rendering (D-01, D-03, TMPL-08).
func (s *HostsServiceImpl) WatchHosts(stream grpc.BidiStreamingServer[hostsv1.WatchHostsRequest, hostsv1.WatchHostsResponse]) error {
	req, err := stream.Recv()
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return err
	}

	if req.GetFollow() {
		return status.Error(codes.Unimplemented, "follow mode is not implemented yet")
	}

	return status.Error(codes.Unimplemented, "one-shot snapshot mode is not implemented yet")
}
