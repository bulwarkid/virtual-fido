package airgap

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"unicode"

	"github.com/fxamacker/cbor/v2"
)

// Operation indicates whether the request is makeCredential or getAssertion.
type Operation uint8

const (
	OpMakeCredential Operation = 1
	OpGetAssertion   Operation = 2
)

// Request is a sanitized, serializable payload sent from the online relay to the vault.
type Request struct {
	Op             Operation `cbor:"1,keyasint"`
	RPID           string    `cbor:"2,keyasint"`
	UserHandle     []byte    `cbor:"3,keyasint,omitempty"`
	ClientDataHash []byte    `cbor:"4,keyasint"`
	AllowList      [][]byte  `cbor:"5,keyasint,omitempty"`
	Label          string    `cbor:"6,keyasint,omitempty"`
}

// Validate ensures required fields are present.
func (r *Request) Validate() error {
	if r.Op != OpMakeCredential && r.Op != OpGetAssertion {
		return errors.New("unsupported op")
	}
	if r.RPID == "" {
		return errors.New("missing rpId")
	}
	if len(r.ClientDataHash) == 0 {
		return errors.New("missing clientDataHash")
	}
	return nil
}

// Response is sent from the vault back to the online relay.
type Response struct {
	Op                Operation `cbor:"1,keyasint"`
	CredentialID      []byte    `cbor:"2,keyasint,omitempty"`
	AuthenticatorData []byte    `cbor:"3,keyasint,omitempty"`
	AttestationObject []byte    `cbor:"4,keyasint,omitempty"`
	Signature         []byte    `cbor:"5,keyasint,omitempty"`
	UserHandle        []byte    `cbor:"6,keyasint,omitempty"`
	SignCount         uint32    `cbor:"7,keyasint,omitempty"`
}

// PacketBatch is a batch of raw HID reports used for online/offline relay.
type PacketBatch struct {
	Reports [][]byte `cbor:"1,keyasint"`
}

// HIDKind identifies CTAP2 (CBOR) vs U2F (MSG).
type HIDKind uint8

const (
	HIDKindCTAP HIDKind = 1
	HIDKindU2F  HIDKind = 2
	HIDKindInit HIDKind = 3
)

// HIDRequest represents a full CTAPHID message (already de-fragmented) to send offline.
type HIDRequest struct {
	Kind    HIDKind `cbor:"1,keyasint"`
	Command uint8   `cbor:"2,keyasint"`
	Payload []byte  `cbor:"3,keyasint"`

	// Optional metadata for prompting.
	RPID     string `cbor:"4,keyasint,omitempty"`
	User     string `cbor:"5,keyasint,omitempty"`
	Op       string `cbor:"6,keyasint,omitempty"`
	AllowLen int    `cbor:"7,keyasint,omitempty"`
}

// HIDResponse carries the payload to return to the host for the given command.
type HIDResponse struct {
	Payload []byte `cbor:"1,keyasint,omitempty"`
	Error   string `cbor:"2,keyasint,omitempty"`
}

// EncodeRequest to hex for copy/paste.
func EncodeRequest(req *Request) (string, error) {
	b, err := cbor.Marshal(req)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// DecodeRequest parses hex input after sanitizing printable ASCII.
func DecodeRequest(s string) (*Request, error) {
	bin, err := sanitizeHex(s)
	if err != nil {
		return nil, err
	}
	var req Request
	if err := cbor.Unmarshal(bin, &req); err != nil {
		return nil, fmt.Errorf("decode request: %w", err)
	}
	return &req, nil
}

// EncodeResponse to hex for copy/paste.
func EncodeResponse(resp *Response) (string, error) {
	b, err := cbor.Marshal(resp)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// EncodePackets encodes a batch of HID reports to hex.
func EncodePackets(batch PacketBatch) (string, error) {
	b, err := cbor.Marshal(batch)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// DecodeResponse parses hex input after sanitizing printable ASCII.
func DecodeResponse(s string) (*Response, error) {
	bin, err := sanitizeHex(s)
	if err != nil {
		return nil, err
	}
	var resp Response
	if err := cbor.Unmarshal(bin, &resp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &resp, nil
}

// DecodePackets parses hex input into a packet batch.
func DecodePackets(s string) (PacketBatch, error) {
	bin, err := sanitizeHex(s)
	if err != nil {
		return PacketBatch{}, err
	}
	var batch PacketBatch
	if err := cbor.Unmarshal(bin, &batch); err != nil {
		return PacketBatch{}, fmt.Errorf("decode packets: %w", err)
	}
	return batch, nil
}

// EncodeHIDRequest encodes HIDRequest to hex.
func EncodeHIDRequest(req *HIDRequest) (string, error) {
	b, err := cbor.Marshal(req)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// DecodeHIDRequest decodes hex to HIDRequest.
func DecodeHIDRequest(s string) (*HIDRequest, error) {
	b, err := sanitizeHex(s)
	if err != nil {
		return nil, err
	}
	var req HIDRequest
	if err := cbor.Unmarshal(b, &req); err != nil {
		return nil, fmt.Errorf("decode hid request: %w", err)
	}
	return &req, nil
}

// EncodeHIDResponse encodes HIDResponse to hex.
func EncodeHIDResponse(resp *HIDResponse) (string, error) {
	b, err := cbor.Marshal(resp)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// DecodeHIDResponse decodes hex to HIDResponse.
func DecodeHIDResponse(s string) (*HIDResponse, error) {
	b, err := sanitizeHex(s)
	if err != nil {
		return nil, err
	}
	var resp HIDResponse
	if err := cbor.Unmarshal(b, &resp); err != nil {
		return nil, fmt.Errorf("decode hid response: %w", err)
	}
	return &resp, nil
}

// PromptYesNo prompts on stdin with default yes.
func PromptYesNo(prompt string) bool {
	fmt.Printf("%s ", prompt)
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "" || line == "y" || line == "yes"
}

// sanitizeHex keeps only printable ASCII, then hex-decodes.
func sanitizeHex(s string) ([]byte, error) {
	var sb strings.Builder
	for _, r := range s {
		if r > unicode.MaxASCII || r < 0x20 {
			continue
		}
		if strings.ContainsRune(" \t\r\n", r) {
			continue
		}
		sb.WriteRune(r)
	}
	clean := sb.String()
	if clean == "" {
		return nil, errors.New("empty input")
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}
	return b, nil
}
