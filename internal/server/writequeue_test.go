package server

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteQueue_SingleWrite(t *testing.T) {
	q := NewWriteQueue(10, slog.Default())
	q.Start()
	defer q.Stop()

	var ran bool
	err := q.Submit(context.Background(), func() error {
		ran = true
		return nil
	})
	require.NoError(t, err)
	assert.True(t, ran)
}

func TestWriteQueue_MultipleSequential(t *testing.T) {
	q := NewWriteQueue(10, slog.Default())
	q.Start()
	defer q.Stop()

	var count int
	for i := 0; i < 5; i++ {
		err := q.Submit(context.Background(), func() error {
			count++
			return nil
		})
		require.NoError(t, err)
	}
	assert.Equal(t, 5, count)
}

func TestWriteQueue_ConcurrentSerialised(t *testing.T) {
	q := NewWriteQueue(100, slog.Default())
	q.Start()
	defer q.Stop()

	var order []int
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			err := q.Submit(context.Background(), func() error {
				// No mutex needed — write queue guarantees serial execution
				order = append(order, n)
				return nil
			})
			assert.NoError(t, err)
		}(i)
	}

	wg.Wait()
	// All 20 should have been processed (order may vary due to goroutine scheduling)
	assert.Len(t, order, 20)
}

func TestWriteQueue_ConcurrentNoDataRace(t *testing.T) {
	q := NewWriteQueue(100, slog.Default())
	q.Start()
	defer q.Stop()

	// Verify that concurrent writes don't race on shared state
	var counter atomic.Int64
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = q.Submit(context.Background(), func() error {
				// Each write increments - since serialised, no race
				counter.Add(1)
				return nil
			})
		}()
	}

	wg.Wait()
	assert.Equal(t, int64(50), counter.Load())
}

func TestWriteQueue_ContextCancellation(t *testing.T) {
	q := NewWriteQueue(1, slog.Default())
	q.Start()
	defer q.Stop()

	// Fill the queue with a blocking write. Signal when process() starts executing it
	// so we know the buffer slot is free and process() is occupied.
	blocker := make(chan struct{})
	processingStarted := make(chan struct{})
	go func() {
		_ = q.Submit(context.Background(), func() error {
			close(processingStarted)
			<-blocker
			return nil
		})
	}()
	<-processingStarted // process() is now blocked; q.ch buffer is empty

	// Fill the buffer slot. Since process() is blocked, the second Submit fast-paths
	// into q.ch (buffer has room) and then blocks waiting for its result. We use a
	// ready channel to know when that goroutine has enqueued the command: we signal
	// from the goroutine right before blocking on Submit, and then spin on len(q.ch)
	// (accessible because this test is in package server) to confirm the enqueue.
	secondReady := make(chan struct{})
	go func() {
		close(secondReady) // about to call Submit
		_ = q.Submit(context.Background(), func() error { return nil })
	}()
	<-secondReady
	// Spin until the command is in the channel buffer. This is deterministic because
	// process() is blocked on blocker and cannot drain q.ch.
	for len(q.ch) == 0 {
		// yield
	}

	// Now submit with an already-cancelled context — buffer is full, slow path is
	// taken, ctx.Done() fires immediately.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := q.Submit(ctx, func() error { return nil })
	assert.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)

	// Unblock the first command.
	close(blocker)
}

func TestWriteQueue_StopDrains(t *testing.T) {
	q := NewWriteQueue(100, slog.Default())
	q.Start()

	var count atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = q.Submit(context.Background(), func() error {
				count.Add(1)
				return nil
			})
		}()
	}

	// Wait for all submits to complete before stopping
	wg.Wait()
	q.Stop()
	assert.Equal(t, int64(10), count.Load())
}

func TestWriteQueue_SubmitAfterStop(t *testing.T) {
	q := NewWriteQueue(10, slog.Default())
	q.Start()
	q.Stop()

	err := q.Submit(context.Background(), func() error { return nil })
	assert.ErrorIs(t, err, ErrQueueStopped)
}

func TestWriteQueue_ConcurrentStopAndSubmit(t *testing.T) {
	// Regression test: concurrent Stop + Submit with a full buffer must not
	// panic with "send on closed channel".
	for range 100 {
		q := NewWriteQueue(1, slog.Default())
		q.Start()

		// Fill the buffer with a slow write so the slow path is exercised.
		blocker := make(chan struct{})
		processingStarted := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = q.Submit(context.Background(), func() error {
				close(processingStarted) // process() is now executing this fn
				<-blocker
				return nil
			})
		}()
		// Wait until the first command is actively being processed (buffer slot free).
		<-processingStarted

		// Enqueue a second command to fill the buffer slot.
		secondReady := make(chan struct{})
		wg.Add(1)
		go func() {
			defer wg.Done()
			close(secondReady) // about to call Submit
			_ = q.Submit(context.Background(), func() error { return nil })
		}()
		<-secondReady
		// Spin until the second command is in the buffer. process() is blocked so
		// it cannot drain q.ch, making this deterministic.
		for len(q.ch) == 0 {
			// yield
		}

		// Submit a third command that will hit the slow path (buffer full),
		// while Stop races to close the channel.
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := q.Submit(context.Background(), func() error { return nil })
			// Accept either success, stopped, or cancelled — no panic is the goal.
			if err != nil {
				assert.True(t,
					errors.Is(err, ErrQueueStopped) || errors.Is(err, context.Canceled),
					"unexpected error: %v", err)
			}
		}()

		// Stop races with the in-flight Submit.
		close(blocker)
		q.Stop()
		wg.Wait()
	}
}

func TestWriteQueue_ErrorPropagation(t *testing.T) {
	q := NewWriteQueue(10, slog.Default())
	q.Start()
	defer q.Stop()

	expectedErr := errors.New("write failed")
	err := q.Submit(context.Background(), func() error {
		return expectedErr
	})
	assert.ErrorIs(t, err, expectedErr)
}
