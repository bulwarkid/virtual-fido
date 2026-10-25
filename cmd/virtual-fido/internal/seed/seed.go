package seed

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"unicode"

	"golang.org/x/crypto/argon2"
)

const (
	argonTime    uint32 = 1         // iterations
	argonMemory  uint32 = 64 * 1024 // KiB (64 MiB)
	argonThreads uint8  = 4
	argonLength  uint32 = 32
)

var argonSalt = []byte("virtual-fido-seed-salt-v1")

// Load reads a hex-encoded seed from a file path or stdin if path is empty.
func Load(path string) ([]byte, error) {
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return parseAndHarden(strings.TrimSpace(string(data)))
	}
	return readFromStdin()
}

func readFromStdin() ([]byte, error) {
	fmt.Fprint(os.Stderr, "Enter seed (hex): ")
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	return parseAndHarden(strings.TrimSpace(line))
}

func parseAndHarden(s string) ([]byte, error) {
	clean := make([]rune, 0, len(s))
	for _, r := range s {
		if unicode.IsSpace(r) {
			continue
		}
		clean = append(clean, r)
	}
	if len(clean) == 0 {
		return nil, errors.New("empty seed")
	}
	b, err := hex.DecodeString(string(clean))
	if err != nil {
		return nil, fmt.Errorf("invalid seed hex: %w", err)
	}
	return harden(b), nil
}

func harden(seed []byte) []byte {
	return argon2.IDKey(seed, argonSalt, argonTime, argonMemory, argonThreads, argonLength)
}
