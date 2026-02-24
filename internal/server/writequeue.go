package server

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/samber/oops"
)

// ErrQueueStopped is returned by Submit when the queue has been stopped.
var ErrQueueStopped = errors.New("write queue stopped")

// writeCommand pairs a write closure with a channel to report the result.
type writeCommand struct {
	fn     func() error
	result chan<- error
}

// WriteQueue serializes concurrent writes through a single goroutine.
type WriteQueue struct {
	ch   chan writeCommand
	quit chan struct{} // closed by Stop to tell process() to drain and exit
	done chan struct{} // closed by process() when it has fully exited
	log  *slog.Logger

	mu      sync.Mutex
	stopped bool
}

// NewWriteQueue creates a queue with the given buffer size.
func NewWriteQueue(bufferSize int, logger *slog.Logger) *WriteQueue {
	return &WriteQueue{
		ch:   make(chan writeCommand, bufferSize),
		quit: make(chan struct{}),
		done: make(chan struct{}),
		log:  logger,
	}
}

// Start launches the processing goroutine.
func (q *WriteQueue) Start() {
	go q.process()
}

// Stop signals the queue to stop accepting new commands, drains any already-
// buffered commands, and waits for the processing goroutine to exit.
// It is safe to call Stop while Submit calls are in-flight.
func (q *WriteQueue) Stop() {
	q.mu.Lock()
	if !q.stopped {
		q.stopped = true
		close(q.quit)
	}
	q.mu.Unlock()
	<-q.done
}

// Submit sends a write function to the queue and blocks until it completes
// or the context is cancelled. Returns ErrQueueStopped if the queue has
// been stopped.
//
// q.ch is never closed externally; only process() exits naturally after
// q.quit is closed. This means a select with case q.ch <- cmd will never
// panic, regardless of timing with Stop().
//
// NOTE: Known trade-off — if the caller's context is cancelled after the
// command is enqueued but before the result arrives, the write may still
// succeed storage-side while the caller receives a context error. Retries
// are safe for event-sourced operations: updates and deletes use optimistic
// concurrency control (version conflict catches duplicates), and AddHost is
// deduplicated by IP+hostname.
func (q *WriteQueue) Submit(ctx context.Context, fn func() error) error {
	result := make(chan error, 1)
	cmd := writeCommand{fn: fn, result: result}

	q.mu.Lock()
	if q.stopped {
		q.mu.Unlock()
		return ErrQueueStopped
	}

	select {
	case q.ch <- cmd:
		q.mu.Unlock()
	default:
		// Buffer full — unlock and do a blocking select.
		// q.done is included so that if Stop() has already been called and
		// process() has exited (closing q.done), we don't block forever.
		// q.ch is never closed, so this select cannot panic.
		q.mu.Unlock()
		select {
		case q.ch <- cmd:
		case <-ctx.Done():
			return oops.Wrapf(ctx.Err(), "write queue submit")
		case <-q.done:
			return ErrQueueStopped
		}
	}

	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return oops.Wrapf(ctx.Err(), "write queue result")
	case <-q.done:
		return ErrQueueStopped
	}
}

// process reads commands from the channel and executes them one at a time.
// It exits when q.quit is closed and the channel buffer is empty.
func (q *WriteQueue) process() {
	defer close(q.done)
	for {
		select {
		case cmd := <-q.ch:
			err := cmd.fn()
			cmd.result <- err
		case <-q.quit:
			// Drain any commands already buffered before exiting.
			for {
				select {
				case cmd := <-q.ch:
					err := cmd.fn()
					cmd.result <- err
				default:
					return
				}
			}
		}
	}
}
