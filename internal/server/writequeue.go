package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
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
	done chan struct{}
	log  *slog.Logger

	mu      sync.Mutex
	stopped bool
}

// NewWriteQueue creates a queue with the given buffer size.
func NewWriteQueue(bufferSize int, logger *slog.Logger) *WriteQueue {
	return &WriteQueue{
		ch:   make(chan writeCommand, bufferSize),
		done: make(chan struct{}),
		log:  logger,
	}
}

// Start launches the processing goroutine.
func (q *WriteQueue) Start() {
	go q.process()
}

// Stop closes the input channel and waits for all pending commands to drain.
// It is safe to call Stop while Submit calls are in-flight.
func (q *WriteQueue) Stop() {
	q.mu.Lock()
	if !q.stopped {
		q.stopped = true
		close(q.ch)
	}
	q.mu.Unlock()
	<-q.done
}

// Submit sends a write function to the queue and blocks until it completes
// or the context is cancelled. Returns ErrQueueStopped if the queue has
// been stopped.
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
		// Buffer full — unlock and do a blocking select
		q.mu.Unlock()
		select {
		case q.ch <- cmd:
		case <-ctx.Done():
			return fmt.Errorf("write queue submit: %w", ctx.Err())
		}
	}

	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return fmt.Errorf("write queue result: %w", ctx.Err())
	}
}

// process reads commands from the channel and executes them one at a time.
func (q *WriteQueue) process() {
	defer close(q.done)
	for cmd := range q.ch {
		err := cmd.fn()
		cmd.result <- err
	}
}
