package server

import (
	"context"
	"fmt"
	"log/slog"
)

// WriteCommand pairs a write closure with a channel to report the result.
type WriteCommand struct {
	Fn     func() error
	Result chan<- error
}

// WriteQueue serializes concurrent writes through a single goroutine.
type WriteQueue struct {
	ch   chan WriteCommand
	done chan struct{}
	log  *slog.Logger
}

// NewWriteQueue creates a queue with the given buffer size.
func NewWriteQueue(bufferSize int, logger *slog.Logger) *WriteQueue {
	return &WriteQueue{
		ch:   make(chan WriteCommand, bufferSize),
		done: make(chan struct{}),
		log:  logger,
	}
}

// Start launches the processing goroutine.
func (q *WriteQueue) Start() {
	go q.process()
}

// Stop closes the input channel and waits for all pending commands to drain.
func (q *WriteQueue) Stop() {
	close(q.ch)
	<-q.done
}

// Submit sends a write function to the queue and blocks until it completes
// or the context is cancelled.
func (q *WriteQueue) Submit(ctx context.Context, fn func() error) error {
	result := make(chan error, 1)
	cmd := WriteCommand{Fn: fn, Result: result}

	select {
	case q.ch <- cmd:
	case <-ctx.Done():
		return fmt.Errorf("write queue submit: %w", ctx.Err())
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
		err := cmd.Fn()
		cmd.Result <- err
	}
}
