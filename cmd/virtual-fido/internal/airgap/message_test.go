package airgap

import "testing"

func TestEncodeDecodeRequest(t *testing.T) {
	req := &Request{Op: OpMakeCredential, RPID: "example.com", ClientDataHash: []byte{1, 2, 3}}
	hexStr, err := EncodeRequest(req)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	out, err := DecodeRequest(hexStr)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.RPID != req.RPID || out.Op != req.Op {
		t.Fatalf("roundtrip mismatch: %#v", out)
	}
}

func TestEncodeDecodeResponse(t *testing.T) {
	resp := &Response{
		Op:                OpMakeCredential,
		CredentialID:      []byte{1, 2, 3},
		AuthenticatorData: []byte{4, 5, 6},
	}
	hexStr, err := EncodeResponse(resp)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	dec, err := DecodeResponse(hexStr)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dec.Op != resp.Op || string(dec.CredentialID) != string(resp.CredentialID) {
		t.Fatalf("roundtrip mismatch: %#v", dec)
	}
}

func TestEncodeDecodePackets(t *testing.T) {
	batch := PacketBatch{Reports: [][]byte{{1, 2, 3, 4}, {5, 6}}}
	hexStr, err := EncodePackets(batch)
	if err != nil {
		t.Fatalf("encode packets: %v", err)
	}
	got, err := DecodePackets(hexStr)
	if err != nil {
		t.Fatalf("decode packets: %v", err)
	}
	if len(got.Reports) != len(batch.Reports) {
		t.Fatalf("len mismatch: %#v", got.Reports)
	}
}

func TestEncodeDecodeHIDRequest(t *testing.T) {
	req := &HIDRequest{Kind: HIDKindCTAP, Command: 0x90, Payload: []byte{1, 2, 3}, RPID: "example.com", User: "u", Op: "makeCredential", AllowLen: 2}
	s, err := EncodeHIDRequest(req)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := DecodeHIDRequest(s)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Kind != req.Kind || got.Command != req.Command || got.RPID != req.RPID || got.User != req.User || got.Op != req.Op || got.AllowLen != req.AllowLen {
		t.Fatalf("mismatch: %#v", got)
	}
}

func TestEncodeDecodeHIDResponse(t *testing.T) {
	resp := &HIDResponse{Payload: []byte{4, 5}, Error: "err"}
	s, err := EncodeHIDResponse(resp)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := DecodeHIDResponse(s)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Error != resp.Error || string(got.Payload) != string(resp.Payload) {
		t.Fatalf("mismatch: %#v", got)
	}
}

func TestSanitizeHex(t *testing.T) {
	s := "  616263\n"
	b, err := sanitizeHex(s)
	if err != nil {
		t.Fatalf("sanitize: %v", err)
	}
	if string(b) != "abc" {
		t.Fatalf("want abc got %q", b)
	}
	if _, err := sanitizeHex(""); err == nil {
		t.Fatalf("expected error on empty")
	}
	if _, err := sanitizeHex("zz"); err == nil {
		t.Fatalf("expected error on bad hex")
	}
}
