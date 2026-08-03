package wait_test

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fzymgc-house/router-hosts/internal/testutil/wait"
)

// fakeTB implements testing.TB well enough to observe how Until and
// UntilValue interact with the interface, without invoking runtime.Goexit
// the way a real *testing.T's Fatalf would. It embeds a nil testing.TB to
// satisfy the interface's unexported method and overrides only the two
// methods wait.Until/wait.UntilValue actually call.
type fakeTB struct {
	testing.TB

	mu          sync.Mutex
	helperCalls int
	fatalfCalls int
	fatalfMsg   string
}

func (f *fakeTB) Helper() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.helperCalls++
}

func (f *fakeTB) Fatalf(format string, args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fatalfCalls++
	f.fatalfMsg = fmt.Sprintf(format, args...)
}

func (f *fakeTB) snapshot() (helperCalls, fatalfCalls int, fatalfMsg string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.helperCalls, f.fatalfCalls, f.fatalfMsg
}

func TestUntil_ReturnsImmediatelyWhenConditionTrueOnFirstEvaluation(t *testing.T) {
	fake := &fakeTB{}
	calls := 0

	wait.Until(fake, time.Second, time.Millisecond, "condition to hold", func() bool {
		calls++
		return true
	})

	if calls != 1 {
		t.Fatalf("expected cond to be evaluated exactly once, got %d", calls)
	}
	if _, fatalfCalls, msg := fake.snapshot(); fatalfCalls != 0 {
		t.Fatalf("expected no Fatalf calls, got %d: %s", fatalfCalls, msg)
	}
}

func TestUntil_ReturnsOnceConditionBecomesTrueOnThirdEvaluation(t *testing.T) {
	fake := &fakeTB{}
	calls := 0

	wait.Until(fake, time.Second, time.Millisecond, "condition to hold", func() bool {
		calls++
		return calls >= 3
	})

	if calls != 3 {
		t.Fatalf("expected cond to be evaluated exactly 3 times, got %d", calls)
	}
	if _, fatalfCalls, msg := fake.snapshot(); fatalfCalls != 0 {
		t.Fatalf("expected no Fatalf calls, got %d: %s", fatalfCalls, msg)
	}
}

func TestUntil_TimesOutAndCallsFatalfExactlyOnceWithDescAndTimeout(t *testing.T) {
	fake := &fakeTB{}
	timeout := 30 * time.Millisecond

	wait.Until(fake, timeout, 5*time.Millisecond, "widget to stabilize", func() bool {
		return false
	})

	_, fatalfCalls, msg := fake.snapshot()
	if fatalfCalls != 1 {
		t.Fatalf("expected exactly one Fatalf call, got %d", fatalfCalls)
	}
	if !strings.Contains(msg, "widget to stabilize") {
		t.Fatalf("expected Fatalf message to contain desc verbatim, got %q", msg)
	}
	if !strings.Contains(msg, timeout.String()) {
		t.Fatalf("expected Fatalf message to contain the timeout duration, got %q", msg)
	}
}

func TestUntil_EvaluatesConditionAtLeastOnceWithZeroTimeout(t *testing.T) {
	fake := &fakeTB{}
	calls := 0

	wait.Until(fake, 0, time.Millisecond, "immediate check", func() bool {
		calls++
		return false
	})

	if calls < 1 {
		t.Fatalf("expected cond to be evaluated at least once even with a zero timeout, got %d", calls)
	}
	if _, fatalfCalls, _ := fake.snapshot(); fatalfCalls != 1 {
		t.Fatalf("expected exactly one Fatalf call on zero-timeout failure, got %d", fatalfCalls)
	}
}

func TestUntil_CallsHelper(t *testing.T) {
	fake := &fakeTB{}

	wait.Until(fake, time.Second, time.Millisecond, "anything", func() bool { return true })

	if helperCalls, _, _ := fake.snapshot(); helperCalls < 1 {
		t.Fatalf("expected Helper to be called at least once, got %d", helperCalls)
	}
}

func TestUntil_FatalfIsRecordedOnTheCallingGoroutine(t *testing.T) {
	fake := &fakeTB{}

	wait.Until(fake, 5*time.Millisecond, time.Millisecond, "goroutine check", func() bool { return false })

	// If Fatalf's recording happened on a different goroutine (e.g. relayed
	// through a channel that this goroutine would need to drain), reading
	// fatalfCalls immediately after Until returns, with no synchronization
	// beyond the call itself having returned, would be a data race under
	// `go test -race`. Passing here demonstrates the recording is visible to
	// the caller synchronously, on the same goroutine that invoked Until.
	if _, fatalfCalls, _ := fake.snapshot(); fatalfCalls != 1 {
		t.Fatalf("expected Fatalf to be recorded synchronously on the caller's goroutine, got %d calls", fatalfCalls)
	}
}

func TestUntilValue_ReturnsFirstValueForWhichPredIsTrue(t *testing.T) {
	fake := &fakeTB{}
	values := []int{1, 2, 3}
	idx := 0

	got := wait.UntilValue(fake, time.Second, time.Millisecond, "value to reach 3",
		func() (int, error) {
			v := values[idx]
			if idx < len(values)-1 {
				idx++
			}
			return v, nil
		},
		func(v int) bool { return v == 3 },
	)

	if got != 3 {
		t.Fatalf("expected 3, got %d", got)
	}
	if _, fatalfCalls, msg := fake.snapshot(); fatalfCalls != 0 {
		t.Fatalf("expected no Fatalf calls, got %d: %s", fatalfCalls, msg)
	}
}

func TestUntilValue_RetriesOnFetchErrorThenSucceedsOnceFetchStopsErroring(t *testing.T) {
	fake := &fakeTB{}
	attempts := 0

	got := wait.UntilValue(fake, time.Second, time.Millisecond, "value to become available",
		func() (string, error) {
			attempts++
			if attempts < 3 {
				return "", errors.New("not ready yet")
			}
			return "ready", nil
		},
		func(v string) bool { return v == "ready" },
	)

	if got != "ready" {
		t.Fatalf("expected %q, got %q", "ready", got)
	}
	if attempts < 3 {
		t.Fatalf("expected at least 3 fetch attempts, got %d", attempts)
	}
	if _, fatalfCalls, msg := fake.snapshot(); fatalfCalls != 0 {
		t.Fatalf("expected no Fatalf calls, got %d: %s", fatalfCalls, msg)
	}
}

func TestUntilValue_TimesOutWithLastErrorInMessage(t *testing.T) {
	fake := &fakeTB{}

	got := wait.UntilValue(fake, 20*time.Millisecond, 5*time.Millisecond, "sidecar status",
		func() (string, error) {
			return "", errors.New("boom: disk unreadable")
		},
		func(string) bool { return false },
	)

	if got != "" {
		t.Fatalf("expected zero value, got %q", got)
	}
	_, fatalfCalls, msg := fake.snapshot()
	if fatalfCalls != 1 {
		t.Fatalf("expected exactly one Fatalf call, got %d", fatalfCalls)
	}
	if !strings.Contains(msg, "sidecar status") {
		t.Fatalf("expected Fatalf message to contain desc verbatim, got %q", msg)
	}
	if !strings.Contains(msg, "boom: disk unreadable") {
		t.Fatalf("expected Fatalf message to contain the last error's text, got %q", msg)
	}
}

func TestUntilValue_TimesOutWithLastObservedValueInMessageWhenNoError(t *testing.T) {
	fake := &fakeTB{}

	got := wait.UntilValue(fake, 20*time.Millisecond, 5*time.Millisecond, "counter to reach 100",
		func() (int, error) { return 42, nil },
		func(v int) bool { return v == 100 },
	)

	if got != 0 {
		t.Fatalf("expected zero value, got %d", got)
	}
	_, fatalfCalls, msg := fake.snapshot()
	if fatalfCalls != 1 {
		t.Fatalf("expected exactly one Fatalf call, got %d", fatalfCalls)
	}
	if !strings.Contains(msg, "counter to reach 100") {
		t.Fatalf("expected Fatalf message to contain desc verbatim, got %q", msg)
	}
	if !strings.Contains(msg, "42") {
		t.Fatalf("expected Fatalf message to contain the last observed value, got %q", msg)
	}
}

func TestUntilValue_EvaluatesFetchAtLeastOnceWithZeroTimeout(t *testing.T) {
	fake := &fakeTB{}
	calls := 0

	wait.UntilValue(fake, 0, time.Millisecond, "immediate fetch",
		func() (int, error) {
			calls++
			return 0, nil
		},
		func(int) bool { return false },
	)

	if calls < 1 {
		t.Fatalf("expected fetch to be evaluated at least once even with a zero timeout, got %d", calls)
	}
}
