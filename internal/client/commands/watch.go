package commands

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	texttemplate "text/template"
	"time"

	"github.com/samber/oops"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
	"github.com/fzymgc-house/router-hosts/internal/atomicfile"
	"github.com/fzymgc-house/router-hosts/internal/client"
	"github.com/fzymgc-house/router-hosts/internal/client/template"
)

// tickerStopBound bounds how long runWatch waits for the status ticker
// goroutine to confirm its own exit after the session context is
// cancelled (review round-3 M3). The wait cannot deadlock — the cancel
// that precedes it has already aborted the RPC the ticker's Send is bound
// to — so this is a warn-and-continue safety net, not a real timeout path.
const tickerStopBound = 5 * time.Second

// watchSessionResult reports whether a runWatch session got at least one
// snapshot all the way to disk. Reported separately from the accompanying
// error (review H5): a session normally keeps running after its first
// successful write and may fail much later, so an error-only return cannot
// tell "never worked" apart from "worked for a while, then lost its
// stream" — and the reconnect loop resets its backoff on the former
// condition regardless of the latter.
type watchSessionResult struct {
	SnapshotWritten bool
}

// watchParams carries everything one runWatch session needs. Grouped into a
// struct, like streamLimits/limitsFrom elsewhere in this package, so no
// call site can pass some fields and forget others.
type watchParams struct {
	client          *client.Client
	tmpl            *texttemplate.Template
	declaredVersion string
	outPath         string
	statusPath      string
	hookCommand     string
	hookTimeout     time.Duration
	policy          WatchPolicy
	health          *sinkHealthState
}

// newWatchCmd creates the "watch" command: a long-lived sink that keeps
// --out current as host data changes (TMPL-05), survives connection loss,
// reloads the consumer's resolver, and reports its own health both upstream
// and to a local sidecar status file (D-11, D-12a, TMPL-08).
func newWatchCmd(policy WatchPolicy) *cobra.Command {
	normalizedPolicy := policy.normalized()

	var (
		templatePath   string
		outPath        string
		execCommand    string
		statusFile     string
		statusInterval time.Duration
		execTimeout    time.Duration
	)

	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Keep a rendered artifact current as host data changes (sink mode)",
		Long: "Open a long-lived WatchHosts stream and keep --out current as host data changes, " +
			"with no polling. Survives connection loss (automatic reconnect with backoff) and " +
			"reports its own health both upstream, on the stream it already holds open, and to " +
			"a local sidecar status file (see --status-file).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Read and parse the template, and declare its contract version,
			// BEFORE opening any connection — the same ordering render.go
			// uses, so a malformed or undeclared template fails without
			// touching the server.
			src, err := os.ReadFile(templatePath)
			if err != nil {
				return oops.Wrapf(err, "reading template %s", templatePath)
			}
			tmpl, err := template.Parse(templatePath, string(src))
			if err != nil {
				return err
			}
			declaredVersion, err := template.DeclaredVersion(tmpl)
			if err != nil {
				return err
			}

			c, err := newClientFromFlags()
			if err != nil {
				return err
			}
			defer func() {
				if err := c.Close(); err != nil {
					slog.Warn("closing client connection", "error", err)
				}
			}()

			statusPath := statusFile
			if statusPath == "" {
				statusPath = defaultStatusPath(outPath)
			}

			// The status-interval flag's own default IS the resolved
			// policy's value (registered below), so an operator who never
			// sets the flag gets the injected policy. Only an explicit
			// --status-interval overrides it — Changed() is what
			// distinguishes "an operator asked for this" from "Cobra filled
			// in a default" (review round-3 M2).
			resolvedInterval := normalizedPolicy.StatusInterval
			if cmd.Flags().Changed("status-interval") {
				resolvedInterval = statusInterval
			}
			effectivePolicy := normalizedPolicy
			effectivePolicy.StatusInterval = resolvedInterval

			// Seed health from disk before the first connection (review
			// M3). A corrupt sidecar must not stop a sink from serving, so
			// a read failure only logs a warning and continues with empty
			// state. A successful load is adopted only when the artifact
			// it describes still exists: otherwise the sidecar would
			// assert a rendered state that is no longer on disk, and the
			// change-ID skip in runWatchCycle would make that permanent.
			// When the artifact is gone, health starts empty instead — the
			// loaded rendered_change_id is discarded, not carried forward.
			health := &sinkHealthState{}
			loaded, loadErr := readSinkStatus(statusPath)
			if loadErr != nil {
				slog.Warn("watch: reading sidecar status failed; starting with empty state", "error", loadErr)
			} else if _, statErr := os.Stat(outPath); statErr == nil {
				health.adopt(loaded)
			}
			health.setContractVersion(declaredVersion)

			// signal.NotifyContext, not commandContext(): this is a
			// long-lived command, and commandContext()'s fixed 30 second
			// one-shot deadline would tear down the stream out from under
			// it. SIGINT/SIGTERM end the command cleanly instead.
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			return runWatchSupervised(ctx, watchParams{
				client:          c,
				tmpl:            tmpl,
				declaredVersion: declaredVersion,
				outPath:         outPath,
				statusPath:      statusPath,
				hookCommand:     execCommand,
				hookTimeout:     execTimeout,
				policy:          effectivePolicy,
				health:          health,
			})
		},
	}

	cmd.Flags().StringVar(&templatePath, "template", "", "path to a text/template file (required)")
	cmd.Flags().StringVar(&outPath, "out", "", "artifact output path (required)")
	cmd.Flags().StringVar(&execCommand, "exec", "", "post-write command run via sh -c after a successful write")
	cmd.Flags().StringVar(&statusFile, "status-file", "", "sidecar status file path (default: <out>.status)")
	cmd.Flags().DurationVar(&statusInterval, "status-interval", normalizedPolicy.StatusInterval,
		"interval between upstream status reports")
	cmd.Flags().DurationVar(&execTimeout, "exec-timeout", defaultPostWriteHookTimeout, "timeout for the post-write command")
	_ = cmd.MarkFlagRequired("template")
	_ = cmd.MarkFlagRequired("out")

	return cmd
}

// runWatch holds one WatchHosts stream session: it sends the opening
// follow=true request (carrying the current health snapshot as its status
// payload), runs a status-reporting ticker and the entry receive loop
// concurrently, and returns once the stream ends.
//
// A per-session context is derived first, and its cancel is deferred
// immediately: this is the M5 fix and it must not be skipped. The status
// ticker below is the sole owner of stream.Send and can block there
// indefinitely on flow control; unlike a server handler (which must
// RETURN to end the RPC), a CLIENT stream is bound to the context it was
// created with, so cancelling sessCtx is what aborts the RPC and releases
// a blocked Send. Because the cancel is deferred, every exit path from
// this function releases the ticker, including a panic — and the ticker
// goroutine must therefore never be started from a context that outlives
// this session.
func runWatch(ctx context.Context, p watchParams) (watchSessionResult, error) {
	sessCtx, sessCancel := context.WithCancel(ctx)
	defer sessCancel()

	stream, err := p.client.Hosts.WatchHosts(sessCtx)
	if err != nil {
		return watchSessionResult{}, oops.Wrapf(err, "opening WatchHosts stream")
	}

	openReq := &hostsv1.WatchHostsRequest{
		Follow: true,
		Status: sinkStatusToProto(p.health.snapshot()),
	}
	if err := stream.Send(openReq); err != nil {
		return watchSessionResult{}, oops.Wrapf(err, "sending opening WatchHosts request")
	}

	// tickerDone is closed by the ticker goroutine on its own return,
	// making its exit observable rather than merely intended (review
	// round-3 M3) — see the wait below.
	tickerDone := make(chan struct{})
	go func() {
		defer close(tickerDone)
		sendStatusTicker(sessCtx, stream, p.policy.StatusInterval, p.health)
	}()

	result, recvErr := runWatchRecvLoop(sessCtx, stream, p)

	// Explicit, not only deferred: this is what actually unblocks a ticker
	// stalled in Send, and it must happen BEFORE the wait below or the wait
	// would deadlock. The deferred sessCancel() above still runs at
	// function return; calling it again here is safe (context.CancelFunc
	// is idempotent).
	sessCancel()

	select {
	case <-tickerDone:
	case <-time.After(tickerStopBound):
		slog.Warn("watch: status ticker did not confirm exit within bound")
	}

	return result, recvErr
}

// sendStatusTicker is the sole owner of stream.Send for the lifetime of a
// watch session, mirroring the server's goroutine split
// (internal/server/watch.go). It reads shared health state only through
// health.snapshot() — never a direct field read, which is the entire
// ownership rule review H4 requires — and returns when ctx is done or a
// Send fails.
func sendStatusTicker(ctx context.Context, stream hostsv1.HostsService_WatchHostsClient, interval time.Duration, health *sinkHealthState) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := stream.Send(&hostsv1.WatchHostsRequest{Status: sinkStatusToProto(health.snapshot())}); err != nil {
				return
			}
		}
	}
}

// runWatchRecvLoop is the sole owner of stream.Recv for the lifetime of a
// watch session. It buffers entries until a SnapshotComplete terminator
// arrives — a partial snapshot is never rendered — applying the plan 03
// entry cap and byte budget before each append and refusing the WHOLE
// snapshot (never truncating) when either is crossed. The entry buffer is
// reset after every terminator and on every refusal, so an interrupted or
// oversized snapshot can never bleed into the next render.
func runWatchRecvLoop(ctx context.Context, stream hostsv1.HostsService_WatchHostsClient, p watchParams) (watchSessionResult, error) {
	var result watchSessionResult
	limits := limitsFrom(p.client)

	var entries []*hostsv1.HostEntry
	var totalBytes int64
	var capExceeded bool

	resetSnapshot := func() {
		entries = nil
		totalBytes = 0
		capExceeded = false
	}

	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return result, nil
		}
		if err != nil {
			return result, oops.Wrapf(err, "receiving WatchHosts response")
		}

		if e := resp.GetEntry(); e != nil {
			if capExceeded {
				continue
			}
			if len(entries) >= limits.entries {
				capExceeded = true
				p.health.recordFailure(streamLimitError(limits.entries))
				writeWatchStatus(p)
				slog.Error("watch: refusing snapshot, entry limit exceeded")
				continue
			}
			size := int64(proto.Size(resp))
			if totalBytes+size > limits.bytes {
				capExceeded = true
				p.health.recordFailure(streamByteLimitError(limits.bytes))
				writeWatchStatus(p)
				slog.Error("watch: refusing snapshot, byte limit exceeded")
				continue
			}
			totalBytes += size
			entries = append(entries, e)
			continue
		}

		comp := resp.GetComplete()
		if comp == nil {
			continue
		}

		if !capExceeded {
			if wrote := runWatchCycle(ctx, p, entries, comp); wrote {
				result.SnapshotWritten = true
			}
		}
		resetSnapshot()
	}
}

// runWatchCycle runs one sink cycle to completion in the exact order D-12a
// requires: the version gate, then the change-ID skip, then render, then
// write, then recordSuccess, then the post-write hook, then the sidecar
// write. Returns true only when a write to p.outPath actually happened.
//
// Failure handling is not uniform (D-12a has three outcomes, not two): a
// version mismatch or a render/write failure never replaces the artifact,
// so the previous one stays byte-identical — recordFailure and an early
// return handle both. Once the write succeeds, recordSuccess has already
// run and is never undone: a subsequent hook failure is recorded as
// reload-failed alongside the new success, never as a reason to roll the
// artifact back — on hook failure it is unknown whether the resolver
// already read the new file, so reverting could leave the file and the
// running resolver actively disagreeing.
func runWatchCycle(ctx context.Context, p watchParams, entries []*hostsv1.HostEntry, comp *hostsv1.SnapshotComplete) bool {
	if err := template.RequireVersion(p.declaredVersion, comp.GetContractVersion()); err != nil {
		slog.Error("watch: refusing snapshot, contract version mismatch", "error", err)
		p.health.recordFailure(err)
		writeWatchStatus(p)
		return false
	}

	changeID := comp.GetChangeId()
	snap := p.health.snapshot()

	// Change-ID skip (D-21 client half, TMPL-08): skip the render, the
	// write, and the hook only when ALL THREE hold — the incoming ID
	// matches the last rendered one, the artifact still exists on disk,
	// and the last reload did not fail. Each guards a different way the
	// skip becomes permanent: without the artifact check, an out-of-band
	// deletion is never repaired (T-1-36); without the reload-health
	// check, a failed resolver reload can never retry, because the
	// artifact already carries the current change ID and every later
	// identical snapshot would otherwise be skipped forever (review M4,
	// T-1-46).
	skipEligible := changeID != "" && changeID == snap.RenderedChangeID && !snap.ReloadFailed
	if skipEligible {
		if _, statErr := os.Stat(p.outPath); statErr == nil {
			slog.Debug("watch: skipping redundant render", "change_id", changeID)
			return false
		}
	}

	data := template.FromProto(entries, comp)
	rendered, err := template.Render(p.tmpl, data)
	if err != nil {
		slog.Error("watch: render failed", "error", err)
		p.health.recordFailure(err)
		writeWatchStatus(p)
		return false
	}

	if err := atomicfile.Write(p.outPath, rendered); err != nil {
		slog.Error("watch: writing artifact failed", "error", err)
		p.health.recordFailure(err)
		writeWatchStatus(p)
		return false
	}

	now := time.Now().UTC()
	p.health.recordSuccess(changeID, now)

	if p.hookCommand != "" {
		if err := runPostWriteHook(ctx, p.hookCommand, p.hookTimeout); err != nil {
			slog.Error("watch: post-write hook failed", "error", err)
			p.health.recordReloadFailure(err, time.Now().UTC())
		} else {
			p.health.recordReloadSuccess(time.Now().UTC())
		}
	}

	writeWatchStatus(p)
	return true
}

// writeWatchStatus writes the current health snapshot to the sidecar,
// logging (never returning) a failure: a sidecar write failure must not
// abort an otherwise-successful cycle.
func writeWatchStatus(p watchParams) {
	if err := writeSinkStatus(p.statusPath, p.health.snapshot()); err != nil {
		slog.Warn("watch: writing sidecar status failed", "error", err)
	}
}

// sinkStatusToProto maps a local sinkStatus onto the wire SinkStatus a
// sink reports upstream. A zero time.Time maps to unix seconds 0 — the
// server's sinkStateFromStatus treats 0 as "never", not as the epoch.
func sinkStatusToProto(st sinkStatus) *hostsv1.SinkStatus {
	out := &hostsv1.SinkStatus{
		ConsecutiveFailures: int32(st.ConsecutiveFailures),
		ContractVersion:     st.ContractVersion,
		RenderedChangeId:    st.RenderedChangeID,
		ReloadFailed:        st.ReloadFailed,
	}
	if !st.LastSuccess.IsZero() {
		out.LastSuccessUnix = st.LastSuccess.Unix()
	}
	if !st.LastReloadSuccess.IsZero() {
		out.LastReloadSuccessUnix = st.LastReloadSuccess.Unix()
	}
	return out
}

// runWatchSupervised wraps runWatch in a reconnect loop with bounded
// exponential backoff. All timing comes from p.policy — no package-level
// backoff variables exist (review H4, L13); the policy is the only source.
//
// A reconnect sends nothing but a fresh follow request: the server keeps no
// per-stream position by design (D-06, D-08), so the next snapshot IS the
// complete current state. Do not add a resume token or cursor here — a
// future reader will be tempted to, and it would reintroduce exactly the
// per-consumer server state D-06/D-08 reject.
func runWatchSupervised(ctx context.Context, p watchParams) error {
	backoff := p.policy.InitialBackoff

	for {
		result, err := runWatch(ctx, p)

		select {
		case <-ctx.Done():
			// The caller is shutting down (SIGINT/SIGTERM or test
			// cancellation); whatever runWatch returned is a byproduct of
			// that, not a real connection failure, so it is not recorded
			// as one.
			return nil
		default:
		}

		if err != nil {
			// D-12a's third outcome: connection loss. The artifact is
			// unchanged and stale; recordFailure preserves last_success and
			// rendered_change_id while incrementing the failure count.
			p.health.recordFailure(err)
			writeWatchStatus(p)
			slog.Warn("watch: session ended, reconnecting", "error", err)
		}

		// The reset keys on the SESSION RESULT, not the error (review H5):
		// a session that connected, wrote successfully, and only later lost
		// its stream must not be treated as a failing endpoint and backed
		// off as though it had never worked. An error-only return cannot
		// express that distinction, because such a session still returns a
		// non-nil error here.
		if result.SnapshotWritten {
			backoff = p.policy.InitialBackoff
		} else {
			backoff *= 2
			if backoff > p.policy.MaxBackoff {
				backoff = p.policy.MaxBackoff
			}
		}

		// Do not clear reload health here: a connection loss says nothing
		// about whether the resolver reloaded, and overwriting
		// reload_failed on reconnect would erase D-12a's middle outcome and
		// suppress the hook retry that flag enables in runWatchCycle.

		wait := p.policy.Jitter(backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}
