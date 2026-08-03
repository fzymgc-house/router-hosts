package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math"
	"time"

	"github.com/oklog/ulid/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
	"github.com/fzymgc-house/router-hosts/internal/contract"
)

// snapshotPageSize is the page size sendSnapshot uses when draining
// ListPage for a WatchHosts snapshot. A package var, not a const, so tests
// can shrink it instead of seeding a large fixture to exercise multiple
// pages — following the MaxTrackedSinks precedent (sinkmetrics.go).
var snapshotPageSize = 500

// TemplateContractVersion is the template data contract version this server
// advertises on every WatchHosts SnapshotComplete terminator. Defined in
// internal/contract and must not be redeclared here.
const TemplateContractVersion = contract.TemplateVersion

// watchHostsStream narrows the gRPC-generated bidi-streaming type to a
// package-local alias so the follow-mode handler and its two goroutines
// don't repeat the full generic instantiation.
type watchHostsStream = grpc.BidiStreamingServer[hostsv1.WatchHostsRequest, hostsv1.WatchHostsResponse]

// WatchHosts implements the bidirectional streaming RPC that serves host
// entries plus a snapshot terminator to a consumer for client-side template
// rendering (D-01, D-03, TMPL-08). The opening request selects one-shot mode
// (a single snapshot, then the RPC ends) or follow mode (a snapshot on
// connect and a fresh one on every subsequent change, until the stream
// closes).
func (s *HostsServiceImpl) WatchHosts(stream watchHostsStream) error {
	// The opening request is read exactly once, here, on the handler
	// goroutine, before follow mode ever spawns a receiver. This is the
	// only read that happens before the goroutine pair exists, so there is
	// never a window with two concurrent readers.
	req, err := stream.Recv()
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return err
	}

	if !req.GetFollow() {
		return s.sendSnapshot(stream.Context(), stream.Send)
	}

	return s.watchFollow(stream, req)
}

// sendSnapshot sends one complete snapshot — every current host entry
// followed by exactly one SnapshotComplete terminator — through send. Shared
// by the one-shot path (WatchHosts, above) and every follow-mode push
// (watchFollowSend, below), so the terminator's shape, and specifically its
// change ID, can never drift between the two modes.
//
// The change ID is derived STRICTLY BEFORE the first ListPage fetch. This
// ordering is the H1 fix from plan 01, carried into follow mode via this
// shared helper, and it is load-bearing: moving the change-ID read after the
// first page fetch reintroduces a bug that no test in the suite catches by
// timing alone.
//
// Deriving the ID first makes it a LOWER BOUND on the snapshot: a mutation
// landing between this read and the entries drain puts entries in the
// snapshot that the ID does not yet name, and the ID is then corrected by
// the next snapshot, which carries a strictly greater ID and therefore does
// not match what the consumer recorded — costing one redundant render.
//
// Deriving the ID LAST produces the opposite and unrecoverable error: the
// snapshot would carry entries from before the mutation labelled with the ID
// from after it, the consumer would record that newer ID against older
// entries, and the mutation's own follow-up snapshot would carry the same ID
// and be skipped by the D-21 client-side dedupe (plan 07) — leaving the
// consumer serving a STALE zone permanently while reporting itself
// converged. No later snapshot changes the ID unless another mutation
// happens to land.
//
// What this ordering does NOT buy: the ID still does not name the entry set
// exactly, because reads are not held under the write queue (which is
// scoped to mutations, service.go), and because ListPage's own consistency
// contract (storage.HostProjection.ListPage, D-09) is per-page, not
// per-drain — each page checks out its own pooled connection. Making it
// exact needs a single transaction {entries, latestEventID} read, which is
// deliberately deferred — see plan 01-01's objective and GitHub issue #401.
// Do not describe the ID as identifying the exact streamed state.
func (s *HostsServiceImpl) sendSnapshot(ctx context.Context, send func(*hostsv1.WatchHostsResponse) error) error {
	latestID, err := s.store.LatestEventID(ctx)
	if err != nil {
		return mapError(err)
	}
	// LatestEventID's contract already maps an empty log to the zero ULID
	// (storage.ZeroChangeID), so its string form is used directly.
	changeID := latestID.String()

	// Drain ListPage rather than materializing the whole inventory in one
	// ListAll call (LAZY-01/LAZY-02): count accumulates across pages because
	// SnapshotComplete.Count has always meant "entries sent", and paging
	// does not change that.
	var count int
	var cursor ulid.ULID
	for {
		page, next, done, pageErr := s.store.ListPage(ctx, cursor, snapshotPageSize)
		if pageErr != nil {
			return mapError(pageErr)
		}
		for i := range page {
			if err := send(&hostsv1.WatchHostsResponse{
				Payload: &hostsv1.WatchHostsResponse_Entry{
					Entry: domainToProto(&page[i]),
				},
			}); err != nil {
				return err
			}
		}
		count += len(page)
		if done {
			break
		}
		cursor = next
	}

	// The client's configured 50,000-entry ceiling does not constrain the
	// server's inventory, so this guard is the server's own: refuse rather
	// than let int32(count) wrap to a negative count (review L7).
	if count > math.MaxInt32 {
		return status.Errorf(codes.Internal, "snapshot entry count %d exceeds int32 range", count)
	}

	// The convergence gauge's real observation point (plan 05's
	// RegisterSinkGauges reads this value at scrape time). Recorded here,
	// once, so both the one-shot path and every follow-mode push keep the
	// server's reported change ID current.
	if s.sinkHealth != nil {
		s.sinkHealth.RecordServerChange(changeID)
	}

	return send(&hostsv1.WatchHostsResponse{
		Payload: &hostsv1.WatchHostsResponse_Complete{
			Complete: &hostsv1.SnapshotComplete{
				Count:           int32(count),
				GeneratedAt:     timestamppb.New(time.Now().UTC()),
				ContractVersion: TemplateContractVersion,
				ChangeId:        changeID,
			},
		},
	})
}

// watchFollow implements the continuous sink. It does five things and
// nothing else: derive a cancellable context from the stream's, resolve the
// caller's identity, spawn a sender and a receiver, then select on the first
// error from either one and return immediately. It never joins the two
// goroutines it spawns.
//
// first is the opening WatchHostsRequest, already read by WatchHosts before
// this function was called — no second read of it happens here.
func (s *HostsServiceImpl) watchFollow(stream watchHostsStream, first *hostsv1.WatchHostsRequest) error {
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()

	// Identity resolution happens once, here, before either goroutine
	// starts, and its result (cn, possibly empty) is handed to the receiver
	// rather than re-derived per message.
	//
	// The server sets tls.RequireAndVerifyClientCert, so a connection cannot
	// reach this handler at all without a CA-verified chain — reaching this
	// error branch means something in the authentication path is not
	// behaving as designed, which is why this logs at warn rather than
	// debug (review L11): a silently rising connected count with no
	// tracked identity would otherwise be the only symptom.
	cn, cnErr := commonNameFromContext(stream.Context())
	if cnErr != nil {
		slog.Warn("watch hosts: peer identity could not be verified; per-identity health disabled for this stream",
			"error", cnErr)
		if s.sinkHealth != nil {
			s.sinkHealth.RecordIdentityFailure()
		}
		cn = ""
	}

	// Connect/Disconnect are unconditional and carry no identity:
	// router_hosts_sinks_connected has no label and needs none, which is
	// also what lets a stream whose identity could not be verified still be
	// counted. The deferred Disconnect running on handler return is the
	// observable the teardown tests below assert on — it is what proves the
	// non-joining handler does not leak a connected count.
	if s.sinkHealth != nil {
		s.sinkHealth.Connect()
		defer s.sinkHealth.Disconnect()
	}

	// A status payload on the OPENING message is recorded too, not
	// discarded (review L3): a reconnecting sink uses the opening message
	// to report what it already has on disk, and dropping it loses a
	// convergence signal at exactly the moment it is most useful. Recorded
	// only against a verified identity — never a caller-supplied
	// substitute (D-13).
	if cn != "" && s.sinkHealth != nil {
		if st := first.GetStatus(); st != nil {
			s.sinkHealth.RecordStatus(cn, sinkStateFromStatus(st))
		}
	}

	// Capacity 2 is load-bearing: both the sender and the receiver must be
	// able to report an error and exit even after this handler has already
	// returned (which is exactly what happens below), and an unbuffered
	// channel would leak whichever one reported second.
	errCh := make(chan error, 2)

	go func() {
		s.watchFollowSend(ctx, stream, errCh)
	}()
	go func() {
		s.watchFollowRecv(stream, cn, errCh)
	}()

	// The handler does not wait for either goroutine before returning:
	// returning from the handler ends the RPC, and ending the RPC is
	// exactly what unblocks both a stalled Send and an idle Recv. go doc
	// google.golang.org/grpc.ServerStream states that SendMsg blocks until
	// there is sufficient flow control, the stream is done, or the stream
	// breaks, and that RecvMsg blocks until a message arrives or the stream
	// is done. Cancelling a context derived from stream.Context() is none
	// of those things and unblocks neither call.
	//
	// Waiting for the goroutines to finish before returning would remove
	// the only mechanism that can unblock them, and would deadlock in
	// exactly two windows: a failed Send while the client stays silent
	// (nothing ever wakes the receiver), and a Send stalled on flow control
	// while the client has called CloseSend (nothing ever wakes the
	// sender). Plan 04's keepalive rescues neither case, because the
	// connection is alive in both — the client is simply not reading, or
	// not writing, on purpose or otherwise. Returning here is the fix.
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return nil
	}
}

// watchFollowSend is the sole owner of stream.Send for the lifetime of a
// follow-mode stream. It reports at most one error (nil on a clean context
// cancellation) to errCh and returns.
func (s *HostsServiceImpl) watchFollowSend(ctx context.Context, stream watchHostsStream, errCh chan<- error) {
	// Subscribe BEFORE sending, then on every wake take a FRESH subscription
	// before sending again. This order is load-bearing in both directions.
	// Subscribing first is what guarantees a mutation landing during a send
	// is never lost: Notify() closes the channel this goroutine is already
	// holding, so the close is waiting to be observed the instant Send
	// returns, no matter how long Send was blocked. Taking the newest
	// channel only after waking — never before sending — is what collapses
	// a burst into at most one further wake instead of compounding a
	// lost-update race across sends. Reordering these two lines produces
	// exactly that silent lost-update bug, and no compiler and no
	// timing-based test catches the inversion by itself.
	ch := s.changes.Subscribe()

	if err := s.sendSnapshot(ctx, stream.Send); err != nil {
		errCh <- err
		return
	}

	for {
		select {
		case <-ctx.Done():
			errCh <- nil
			return
		case <-ch:
			ch = s.changes.Subscribe()
			if err := s.sendSnapshot(ctx, stream.Send); err != nil {
				errCh <- err
				return
			}
		}
	}
}

// watchFollowRecv is the sole owner of stream.Recv for the lifetime of a
// follow-mode stream. It records any status payload it receives against cn
// (skipped entirely when cn is empty — an unverified identity is never
// substituted with anything the caller supplied, D-13) and reports at most
// one error (nil on a clean client hangup) to errCh before returning.
func (s *HostsServiceImpl) watchFollowRecv(stream watchHostsStream, cn string, errCh chan<- error) {
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			errCh <- nil
			return
		}
		if err != nil {
			errCh <- err
			return
		}
		if cn == "" || s.sinkHealth == nil {
			continue
		}
		if st := req.GetStatus(); st != nil {
			s.sinkHealth.RecordStatus(cn, sinkStateFromStatus(st))
		}
	}
}

// sinkStateFromStatus maps a consumer-reported SinkStatus onto plan 05's
// SinkState. Unix-seconds fields of 0 map to the zero time.Time, not to the
// 1970 epoch, since a sink that has never rendered has no "last success" to
// report at all.
//
// D-21 is a hard boundary and this is where someone will cross it: this
// function, and RecordStatus's caller above, are the ONLY places
// rendered_change_id is read. Nothing in watchFollowSend, or in
// sendSnapshot, may read it, compare it, or use it to decide whether to
// send a snapshot — doing so would turn it into a server-side resume token,
// which requires exactly the per-consumer position tracking D-06 and D-08
// reject. The client-side skip in plan 07 is the permitted half of the same
// optimization; a server-side skip is the forbidden half, and it is a
// natural-sounding efficiency win someone will propose later. Don't.
func sinkStateFromStatus(st *hostsv1.SinkStatus) SinkState {
	var out SinkState
	if v := st.GetLastSuccessUnix(); v != 0 {
		out.LastSuccess = time.Unix(v, 0).UTC()
	}
	out.ConsecutiveFailures = int64(st.GetConsecutiveFailures())
	out.ContractVersion = st.GetContractVersion()
	out.RenderedChangeID = st.GetRenderedChangeId()
	out.ReloadFailed = st.GetReloadFailed()
	if v := st.GetLastReloadSuccessUnix(); v != 0 {
		out.LastReloadSuccess = time.Unix(v, 0).UTC()
	}
	return out
}
