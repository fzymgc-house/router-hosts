package server

import "sync"

// changeNotifier is a fan-out wake-up primitive: any number of subscribers
// can wait on it, and a single Notify releases every one of them
// simultaneously. It is built on the channel-close-as-broadcast pattern —
// closing a channel is the only Go primitive that wakes every receiver
// blocked on it at once, whether there are zero receivers or a thousand.
//
// This is deliberately NOT a hookRunner clone (see hookrunner.go). hookRunner
// is a process-wide singleton with a single pending-request slot: it
// coalesces triggers for one background consumer. changeNotifier fans out to
// an unbounded number of independent subscribers, each of which resubscribes
// after waking, and none of which shares state with any other.
//
// Guarantee this primitive makes, stated precisely (review M2): a change
// arriving while a subscriber is busy — mid-send, or in the window between
// waking and resubscribing — produces AT MOST ONE additional wake. Taking
// the current channel after waking is what gives burst coalescing: a
// subscriber busy through five notifications reads state once, and reads the
// newest state, never an intermediate one.
//
// Guarantee this primitive does NOT make: that N notifications produce fewer
// than N wakes. If a subscriber's resubscribe happens to interleave with
// every notification, every notification legitimately produces its own wake,
// and that is correct behavior, not a bug. Do not describe this type as
// coalescing "one wake per burst" — it is not true, and a test asserting a
// strict lower bound on wake count will flake under an unfavorable schedule.
type changeNotifier struct {
	mu sync.Mutex
	ch chan struct{}
}

// newChangeNotifier returns a notifier ready to subscribe to and notify.
func newChangeNotifier() *changeNotifier {
	return &changeNotifier{ch: make(chan struct{})}
}

// Subscribe returns the current generation channel. It is closed by the next
// Notify call, which is the caller's wake signal. A subscriber that wants to
// keep waiting for further changes must call Subscribe again after waking —
// the channel returned here is single-use, since a closed channel stays
// closed forever.
func (n *changeNotifier) Subscribe() <-chan struct{} {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.ch
}

// Notify wakes every current subscriber by closing the current generation
// channel, then installs a fresh one for whatever subscribes next. Safe to
// call with zero subscribers: closing a channel nobody is receiving from
// neither blocks nor panics.
func (n *changeNotifier) Notify() {
	n.mu.Lock()
	defer n.mu.Unlock()
	close(n.ch)
	n.ch = make(chan struct{})
}
