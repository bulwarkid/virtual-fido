//go:build linux

package uhid

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"os"
	"strings"
	"time"
)

const (
	// Event types from linux/uapi/linux/uhid.h.
	uhidEventDestroy = 1  // UHID_DESTROY
	uhidEventOutput  = 6  // UHID_OUTPUT
	uhidEventCreate2 = 11 // UHID_CREATE2
	uhidEventInput2  = 12 // UHID_INPUT2

	// HID_MAX_DESCRIPTOR_SIZE from linux/hid.h.
	hidMaxDescriptorSize = 4096
	// Fixed CTAPHID report size.
	reportSize = 64

	// UHID create2 field sizes from struct uhid_create2 in linux/uhid.h.
	uhidNameLen  = 128
	uhidPhysLen  = 64
	uhidUniqLen  = 64
	uhidBusUSB   = 0x03
	uhidVendorID = 0x0D0C
	uhidProduct  = 0x0001

	uhidEventHeaderLen = 4 // __u32 type

	// Largest union member is create2; size its payload and add the header.
	create2PayloadMax = uhidNameLen + uhidPhysLen + uhidUniqLen +
		2 + // rd_size
		2 + // bus
		4 + // vendor
		4 + // product
		4 + // version
		4 + // country
		hidMaxDescriptorSize
	uhidEventSize = uhidEventHeaderLen + create2PayloadMax

	// Output event layout (struct uhid_output).
	outputPayloadMax   = hidMaxDescriptorSize + 2 + 1 // data + size + rtype
	outputSizeOffset   = hidMaxDescriptorSize
	outputRTypeOffset  = hidMaxDescriptorSize + 2
	outputPayloadStart = uhidEventHeaderLen

	// Input event payload max (size + data).
	input2PayloadMax = 2 + hidMaxDescriptorSize
)

// Device represents a UHID-backed virtual HID device.
type Device struct {
	f *os.File
}

// Open creates a UHID device with the provided report descriptor.
func Open(name string, reportDescriptor []byte) (*Device, error) {
	f, err := os.OpenFile("/dev/uhid", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	if len(reportDescriptor) > hidMaxDescriptorSize {
		f.Close()
		return nil, errors.New("report descriptor too large")
	}
	create := buildCreateEvent(name, reportDescriptor)
	if _, err := f.Write(create); err != nil {
		f.Close()
		return nil, err
	}
	return &Device{f: f}, nil
}

// Close tears down the UHID device.
func (d *Device) Close() error {
	if d.f == nil {
		return nil
	}
	d.f.Write(buildDestroyEvent())
	return d.f.Close()
}

// ReadReport blocks for an output report from the host.
func (d *Device) ReadReport(ctx context.Context) ([]byte, error) {
	for {
		buf := make([]byte, uhidEventSize)
		if _, err := io.ReadFull(d.f, buf); err != nil {
			return nil, err
		}
		if report, ok := parseOutputEvent(buf); ok {
			return report, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
	}
}

// parseOutputEvent extracts a 64-byte HID report from a UHID_OUTPUT event.
// Returns ok=false if the event is not UHID_OUTPUT or not a valid 64-byte report.
func parseOutputEvent(ev []byte) ([]byte, bool) {
	if len(ev) < outputPayloadStart+outputPayloadMax {
		return nil, false
	}
	if binary.LittleEndian.Uint32(ev[:uhidEventHeaderLen]) != uhidEventOutput {
		return nil, false
	}
	size := int(binary.LittleEndian.Uint16(ev[outputPayloadStart+outputSizeOffset:]))
	if size > hidMaxDescriptorSize {
		size = hidMaxDescriptorSize
	}
	data := ev[outputPayloadStart : outputPayloadStart+size]
	if len(data) == reportSize+1 && data[0] == 0x00 {
		data = data[1:]
	}
	if len(data) != reportSize {
		debugLog("uhid output unexpected size=%d rawlen=%d", len(data), size)
		return nil, false
	}
	return append([]byte{}, data...), true
}

// WriteReport sends an input report to the host.
func (d *Device) WriteReport(ctx context.Context, report []byte) error {
	if len(report) != reportSize {
		return errors.New("report must be 64 bytes")
	}
	ev := buildInputEvent(report)
	if _, err := d.f.Write(ev); err != nil {
		return err
	}
	debugLog("uhid input: wrote %d bytes", len(report))
	return nil
}

// WaitReady waits briefly to allow the kernel to finish setup.
func (d *Device) WaitReady() {
	time.Sleep(50 * time.Millisecond)
}

var debugEnabled = strings.ToLower(os.Getenv("VIRTUAL_FIDO_DEBUG")) == "1" || strings.ToLower(os.Getenv("VIRTUAL_FIDO_DEBUG")) == "true"

func debugLog(format string, args ...any) {
	if debugEnabled {
		log.Printf(format, args...)
	}
}
