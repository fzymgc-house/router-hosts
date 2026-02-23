package server

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

	// Fill the queue with a blocking write
	blocker := make(chan struct{})
	go func() {
		_ = q.Submit(context.Background(), func() error {
			<-blocker
			return nil
		})
	}()

	// Give the blocking write time to start processing
	time.Sleep(50 * time.Millisecond)

	// Fill the buffer
	go func() {
		_ = q.Submit(context.Background(), func() error { return nil })
	}()
	time.Sleep(50 * time.Millisecond)

	// Now submit with cancelled context - should fail on send
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := q.Submit(ctx, func() error { return nil })
	assert.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)

	// Unblock
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
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = q.Submit(context.Background(), func() error {
				<-blocker
				return nil
			})
		}()
		// Give the blocker time to enter the processor.
		time.Sleep(time.Millisecond)

		// Enqueue a second command to fill the buffer slot.
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = q.Submit(context.Background(), func() error { return nil })
		}()
		time.Sleep(time.Millisecond)

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
