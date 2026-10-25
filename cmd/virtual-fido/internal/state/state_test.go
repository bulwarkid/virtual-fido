package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.bin")
	seed := []byte("seed-1234567890seed-1234567890")
	store := NewStore(path, seed)

	v := &Vault{Counters: map[string]uint32{"cred": 5}, AuthenticationCounter: 7}
	if err := store.Save(v); err != nil {
		t.Fatalf("save: %v", err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Size() == 0 {
		t.Fatalf("state file missing or empty")
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Counters["cred"] != 5 || loaded.AuthenticationCounter != 7 {
		t.Fatalf("loaded mismatch: %#v", loaded)
	}
}

func TestHashSeed(t *testing.T) {
	h := HashSeed([]byte("abc"))
	if len(h) != 8 {
		t.Fatalf("hash length=%d want 8", len(h))
	}
}

func TestVaultString(t *testing.T) {
	v := &Vault{
		Counters: map[string]uint32{
			string([]byte{0x01, 0x02}): 3,
		},
		AuthenticationCounter: 9,
	}
	out := v.String()
	if !strings.Contains(out, "AuthenticationCounter=9") {
		t.Fatalf("missing auth counter in output: %q", out)
	}
	if !strings.Contains(out, "0102") || !strings.Contains(out, "3") {
		t.Fatalf("missing counter detail: %q", out)
	}
}
