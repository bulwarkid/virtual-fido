//go:build linux

package uhid

import (
	"encoding/binary"
	"testing"
)

func TestBuildCreateEvent(t *testing.T) {
	rd := []byte{1, 2, 3}
	ev := buildCreateEvent("TestName", rd)
	if len(ev) != uhidEventSize {
		t.Fatalf("create event size=%d want=%d", len(ev), uhidEventSize)
	}
	if binary.LittleEndian.Uint32(ev[:uhidEventHeaderLen]) != uhidEventCreate2 {
		t.Fatalf("header type mismatch")
	}
	name := string(ev[uhidEventHeaderLen : uhidEventHeaderLen+uhidNameLen])
	if name[:len("TestName")] != "TestName" {
		t.Fatalf("name not written")
	}
	offset := uhidEventHeaderLen + uhidNameLen + uhidPhysLen + uhidUniqLen
	if got := binary.LittleEndian.Uint16(ev[offset:]); got != uint16(len(rd)) {
		t.Fatalf("rd_size=%d want=%d", got, len(rd))
	}
	if vend := binary.LittleEndian.Uint32(ev[offset+4:]); vend != uhidVendorID {
		t.Fatalf("vendor=%x want=%x", vend, uhidVendorID)
	}
	if prod := binary.LittleEndian.Uint32(ev[offset+8:]); prod != uhidProduct {
		t.Fatalf("product=%x want=%x", prod, uhidProduct)
	}
}

func TestBuildInputEvent(t *testing.T) {
	report := make([]byte, reportSize)
	report[0] = 0xAA
	ev := buildInputEvent(report)
	if len(ev) != uhidEventSize {
		t.Fatalf("input event size=%d want=%d", len(ev), uhidEventSize)
	}
	if binary.LittleEndian.Uint32(ev[:uhidEventHeaderLen]) != uhidEventInput2 {
		t.Fatalf("header type mismatch")
	}
	size := binary.LittleEndian.Uint16(ev[uhidEventHeaderLen:])
	if int(size) != len(report) {
		t.Fatalf("size=%d want=%d", size, len(report))
	}
	data := ev[uhidEventHeaderLen+2 : uhidEventHeaderLen+2+len(report)]
	if data[0] != 0xAA {
		t.Fatalf("report not copied")
	}
}

func TestBuildDestroyEvent(t *testing.T) {
	ev := buildDestroyEvent()
	if len(ev) != uhidEventSize {
		t.Fatalf("destroy event size=%d want=%d", len(ev), uhidEventSize)
	}
	if binary.LittleEndian.Uint32(ev[:uhidEventHeaderLen]) != uhidEventDestroy {
		t.Fatalf("header type mismatch")
	}
}

func TestParseOutputEvent(t *testing.T) {
	ev := make([]byte, uhidEventSize)
	binary.LittleEndian.PutUint32(ev[:uhidEventHeaderLen], uhidEventOutput)
	payload := ev[outputPayloadStart:]
	// prepend report ID byte and ensure normalization to 64 bytes.
	data := append([]byte{0x00}, make([]byte, reportSize)...)
	copy(payload, data)
	binary.LittleEndian.PutUint16(payload[outputSizeOffset:], uint16(len(data)))
	report, ok := parseOutputEvent(ev)
	if !ok {
		t.Fatalf("expected parse success")
	}
	if len(report) != reportSize {
		t.Fatalf("report len=%d want=%d", len(report), reportSize)
	}
}
