package server

import (
	"errors"
	"io"
	"math"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

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
		// Plan 06 replaces this branch with the concurrent goroutine pair
		// that implements the continuous sink.
		return status.Error(codes.Unimplemented, "follow mode is not implemented yet")
	}

	ctx := stream.Context()

	// The change ID is derived STRICTLY BEFORE ListAll. This ordering is the
	// H1 fix and it is load-bearing: swapping these two calls reintroduces a
	// bug that no test in the suite catches by timing alone.
	//
	// Deriving the ID first makes it a LOWER BOUND on the snapshot: a
	// mutation landing between this read and ListAll puts entries in the
	// snapshot that the ID does not yet name, and the ID is then corrected
	// by the next snapshot, which carries a strictly greater ID and
	// therefore does not match what the consumer recorded — costing one
	// redundant render.
	//
	// Deriving the ID LAST produces the opposite and unrecoverable error:
	// the snapshot would carry entries from before the mutation labelled
	// with the ID from after it, the consumer would record that newer ID
	// against older entries, and the mutation's own follow-up snapshot
	// would carry the same ID and be skipped by the D-21 client-side dedupe
	// (plan 07) — leaving the consumer serving a STALE zone permanently
	// while reporting itself converged. No later snapshot changes the ID
	// unless another mutation happens to land.
	//
	// What this ordering does NOT buy: the ID still does not name the entry
	// set exactly, because reads are not held under the write queue (which
	// is scoped to mutations, service.go:784). Making it exact needs a
	// single-transaction {entries, latestEventID} read, which is
	// deliberately deferred — see plan 01-01's objective and the follow-up
	// issue filed alongside #400. Do not describe the ID as identifying the
	// exact streamed state.
	latestID, err := s.store.LatestEventID(ctx)
	if err != nil {
		return mapError(err)
	}
	// LatestEventID's contract already maps an empty log to the zero ULID
	// (storage.ZeroChangeID), so its string form is used directly.
	changeID := latestID.String()

	entries, err := s.store.ListAll(ctx)
	if err != nil {
		return mapError(err)
	}

	for i := range entries {
		if err := stream.Send(&hostsv1.WatchHostsResponse{
			Payload: &hostsv1.WatchHostsResponse_Entry{
				Entry: domainToProto(&entries[i]),
			},
		}); err != nil {
			return err
		}
	}

	// The client's configured 50,000-entry ceiling does not constrain the
	// server's inventory, so this guard is the server's own: refuse rather
	// than let int32(len(entries)) wrap to a negative count (review L7).
	if len(entries) > math.MaxInt32 {
		return status.Errorf(codes.Internal, "snapshot entry count %d exceeds int32 range", len(entries))
	}

	return stream.Send(&hostsv1.WatchHostsResponse{
		Payload: &hostsv1.WatchHostsResponse_Complete{
			Complete: &hostsv1.SnapshotComplete{
				Count:           int32(len(entries)),
				GeneratedAt:     timestamppb.New(time.Now().UTC()),
				ContractVersion: TemplateContractVersion,
				ChangeId:        changeID,
			},
		},
	})
}
