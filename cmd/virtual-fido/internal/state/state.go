package state

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/hkdf"
)

// Vault holds persisted counters keyed by credential ID.
// AuthenticationCounter is the global U2F-style counter.
type Vault struct {
	// Counters is runtime-only map keyed by raw credential bytes (string form).
	Counters map[string]uint32 `cbor:"-"`
	Entries  []CounterEntry    `cbor:"1,keyasint,omitempty"`

	AuthenticationCounter uint32 `cbor:"2,keyasint"`
}

// CounterEntry is the on-disk form of a counter, keeping raw bytes (no hex).
type CounterEntry struct {
	ID    []byte `cbor:"1,keyasint"`
	Count uint32 `cbor:"2,keyasint"`
}

// Store persists Vault as encrypted CBOR using a key derived from seed.
type Store struct {
	path string
	key  []byte
}

// NewStore creates or loads a store at path using seed-derived key.
func NewStore(path string, seed []byte) *Store {
	return &Store{
		path: path,
		key:  deriveKey(seed),
	}
}

// Load returns the stored vault (or an empty one if file missing).
func (s *Store) Load() (*Vault, error) {
	if s.path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Vault{Counters: map[string]uint32{}}, nil
		}
		return nil, err
	}
	if len(data) < 1+12 {
		return nil, errors.New("state file too small")
	}
	if data[0] != 1 {
		return nil, errors.New("unsupported state version")
	}
	nonce := data[1 : 1+12]
	ct := data[1+12:]
	plain, err := decrypt(s.key, nonce, ct)
	if err != nil {
		return nil, err
	}
	var v Vault
	if err := cbor.Unmarshal(plain, &v); err != nil {
		return nil, err
	}
	populateCounters(&v)
	return &v, nil
}

// Save writes the vault atomically.
func (s *Store) Save(v *Vault) error {
	if v == nil {
		return errors.New("vault nil")
	}
	if s.path == "" {
		return nil
	}
	populateEntries(v)
	plain, err := cbor.Marshal(v)
	if err != nil {
		return err
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	ct, err := encrypt(s.key, nonce, plain)
	if err != nil {
		return err
	}
	buf := append([]byte{1}, append(nonce, ct...)...)
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".vault-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(buf); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

func deriveKey(seed []byte) []byte {
	if len(seed) == 0 {
		panic("seed required")
	}
	h := hkdf.New(sha256.New, seed, nil, []byte("virtual-fido:vault"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(h, key); err != nil {
		panic(err)
	}
	return key
}

func encrypt(key, nonce, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce, data, nil), nil
}

func decrypt(key, nonce, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, data, nil)
}

// HashSeed returns a short fingerprint of the seed for logging.
func HashSeed(seed []byte) string {
	m := hmac.New(sha256.New, []byte("virtual-fido:fingerprint"))
	m.Write(seed)
	sum := m.Sum(nil)
	return hex.EncodeToString(sum[:4])
}

// String returns a human-readable snapshot of vault contents.
func (v *Vault) String() string {
	if v == nil {
		return "<nil vault>"
	}
	var b strings.Builder
	b.WriteString("AuthenticationCounter=")
	b.WriteString(strconv.FormatUint(uint64(v.AuthenticationCounter), 10))
	b.WriteString("\n")

	keys := make([]string, 0, len(v.Counters))
	for k := range v.Counters {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	b.WriteString("Counters:\n")
	for _, k := range keys {
		count := v.Counters[k]
		b.WriteString("  ")
		b.WriteString(hex.EncodeToString([]byte(k)))
		b.WriteString(": ")
		b.WriteString(strconv.FormatUint(uint64(count), 10))
		b.WriteByte('\n')
	}
	if len(keys) == 0 {
		b.WriteString("  (none)\n")
	}
	return b.String()
}

// populateCounters initializes the Counters map from Entries for in-memory use.
func populateCounters(v *Vault) {
	if v.Counters == nil {
		v.Counters = make(map[string]uint32, len(v.Entries))
	}
	for _, e := range v.Entries {
		v.Counters[string(e.ID)] = e.Count
	}
}

// populateEntries rebuilds Entries from Counters before persisting.
func populateEntries(v *Vault) {
	if v.Counters == nil {
		v.Counters = map[string]uint32{}
	}
	v.Entries = v.Entries[:0]
	for k, c := range v.Counters {
		v.Entries = append(v.Entries, CounterEntry{
			ID:    []byte(k),
			Count: c,
		})
	}
}
