package server

import (
	"context"
	"log/slog"
	"sync"
)

// hookRunRequest carries the plain data needed to run one hook batch. It
// MUST NOT carry a context.Context — a stored RPC context would be cancelled
// when the gRPC handler returns and would race the just-detached hook run.
type hookRunRequest struct {
	event      string
	entryCount int
	errMsg     string
}

// hookRunner detaches hook execution from the RPC write path onto a
// background goroutine running against a server-lifecycle context, with a
// single coalesced pending slot (queue depth 1, latest-wins).
type hookRunner struct {
	exec *HookExecutor
	log  *slog.Logger

	mu      sync.Mutex
	pending *hookRunRequest
	stopped bool

	trigger chan struct{}
	ctx     context.Context
	cancel  context.CancelFunc
	quit    chan struct{}
	done    chan struct{}
}

// newHookRunner creates a runner whose base context is server-lifecycle
// (context.WithCancel(context.Background())), never derived from an RPC
// context.
func newHookRunner(exec *HookExecutor, logger *slog.Logger) *hookRunner {
	ctx, cancel := context.WithCancel(context.Background())
	return &hookRunner{
		exec:    exec,
		log:     logger,
		trigger: make(chan struct{}, 1),
		ctx:     ctx,
		cancel:  cancel,
		quit:    make(chan struct{}),
		done:    make(chan struct{}),
	}
}

// Start launches the processing goroutine.
func (r *hookRunner) Start() {
	go r.loop()
}

// Trigger enqueues req, coalescing with any not-yet-started pending request
// (latest-wins). Never blocks and never touches hook I/O; safe to call from
// the RPC goroutine. When req supersedes an already-pending request, records
// router_hosts_hook_runs_coalesced_total exactly once — the superseded
// request is dropped and will never execute.
func (r *hookRunner) Trigger(req hookRunRequest) {
	r.mu.Lock()
	coalesced := r.pending != nil
	r.pending = &req
	r.mu.Unlock()

	if coalesced {
		r.log.Debug("hook run coalesced", "event", req.event)
		r.exec.metrics.RecordHookRunCoalesced(context.Background(), req.event)
	}

	select {
	case r.trigger <- struct{}{}:
	default:
		// A wakeup is already pending; loop() will pick up the latest req.
	}
}

// Stop signals the loop to drain its single pending request and exit. It
// waits for the goroutine to fully exit, up to ctx's deadline; if the
// deadline fires first, it cancels the runner's base context (killing any
// still-running hook subprocess) and then waits for exit. Safe to call more
// than once.
func (r *hookRunner) Stop(ctx context.Context) {
	r.mu.Lock()
	if !r.stopped {
		r.stopped = true
		close(r.quit)
	}
	r.mu.Unlock()

	select {
	case <-r.done:
	case <-ctx.Done():
		r.cancel()
		<-r.done
	}
}

// loop processes trigger wakeups until quit is closed, then drains any
// single still-pending request before exiting.
func (r *hookRunner) loop() {
	defer close(r.done)
	for {
		select {
		case <-r.trigger:
			r.runPending()
		case <-r.quit:
			r.runPending()
			return
		}
	}
}

// runPending takes and clears the pending request, running it if present.
func (r *hookRunner) runPending() {
	r.mu.Lock()
	req := r.pending
	r.pending = nil
	r.mu.Unlock()
	if req != nil {
		r.runBatch(*req)
	}
}

// runBatch dispatches a request to the executor's synchronous core, always
// using the runner's own server-lifecycle context — never an RPC context.
func (r *hookRunner) runBatch(req hookRunRequest) {
	r.log.Info("hook batch starting", "event", req.event, "entry_count", req.entryCount)
	if req.event == "success" {
		r.exec.RunSuccess(r.ctx, req.entryCount)
	} else {
		r.exec.RunFailure(r.ctx, req.entryCount, req.errMsg)
	}
}
