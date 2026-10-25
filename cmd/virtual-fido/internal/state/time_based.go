package state

import "time"

// TimeBasedCounterStore is a CounterState that keeps counters in memory and seeds
// values from a base timestamp to keep them monotonic without persistence.
type TimeBasedCounterStore struct {
	base       int64
	now        func() time.Time
	credCounts map[string]uint32
	global     uint32
}

// NewTimeBasedCounterStore creates an in-memory counter store using the given base epoch
// (seconds) and a time source. If base is zero, a default of 1765000000 is used.
func NewTimeBasedCounterStore(base int64, now func() time.Time) *TimeBasedCounterStore {
	if base == 0 {
		base = 1765000000
	}
	if now == nil {
		now = time.Now
	}
	return &TimeBasedCounterStore{base: base, now: now, credCounts: map[string]uint32{}}
}

// IncrementCred increments and returns the per-credential counter.
func (t *TimeBasedCounterStore) IncrementCred(id []byte) uint32 {
	key := encodeKey(id)
	next := t.nextValue(t.credCounts[key])
	t.credCounts[key] = next
	return next
}

// EnsureCred initializes a credential counter to zero if absent.
func (t *TimeBasedCounterStore) EnsureCred(id []byte) {
	key := encodeKey(id)
	if _, ok := t.credCounts[key]; !ok {
		t.credCounts[key] = 0
	}
}

// CredValue returns the stored counter and whether it exists.
func (t *TimeBasedCounterStore) CredValue(id []byte) (uint32, bool) {
	val, ok := t.credCounts[encodeKey(id)]
	return val, ok
}

// SetCred sets the counter to the given value.
func (t *TimeBasedCounterStore) SetCred(id []byte, v uint32) {
	t.credCounts[encodeKey(id)] = v
}

// IncrementGlobal increments the global authentication counter (U2F style).
func (t *TimeBasedCounterStore) IncrementGlobal() uint32 {
	t.global = t.nextValue(t.global)
	return t.global
}

func (t *TimeBasedCounterStore) nextValue(last uint32) uint32 {
	sec := t.now().Unix() - t.base
	if sec < 0 {
		sec = 0
	}
	candidate := uint32(sec)
	if candidate <= last {
		candidate = last + 1
	}
	return candidate
}
