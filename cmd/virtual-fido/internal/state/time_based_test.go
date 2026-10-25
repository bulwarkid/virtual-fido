package state

import (
	"testing"
	"time"
)

func TestTimeBasedCounterMonotonic(t *testing.T) {
	base := int64(1765000000)
	ts := base + 10
	now := func() time.Time { return time.Unix(ts, 0) }
	m := NewTimeBasedCounterStore(base, now)

	if v := m.IncrementCred([]byte("a")); v != 10 {
		t.Fatalf("got %d want 10", v)
	}
	if v := m.IncrementCred([]byte("a")); v != 11 {
		t.Fatalf("got %d want 11", v)
	}
	if v := m.IncrementGlobal(); v != 10 {
		t.Fatalf("global %d want 10", v)
	}
	ts = base + 5
	if v := m.IncrementCred([]byte("a")); v != 12 {
		t.Fatalf("backwards time got %d want 12", v)
	}
	ts = base + 20
	if v := m.IncrementCred([]byte("b")); v != 20 {
		t.Fatalf("new cred got %d want 20", v)
	}
}
