package usb

import (
	"sync"
	"testing"
)

type recordingDelegate struct {
	lock    sync.Mutex
	packets []byte
}

func (delegate *recordingDelegate) HandleMessage(packet []byte) {
	delegate.lock.Lock()
	defer delegate.lock.Unlock()
	delegate.packets = append(delegate.packets, packet[0])
}

func (delegate *recordingDelegate) SetResponseHandler(handler func(response []byte)) {}

func TestInputPacketsDeliveredInOrder(t *testing.T) {
	delegate := &recordingDelegate{}
	device := NewUSBDevice(delegate)
	for i := 0; i < 200; i++ {
		device.HandleMessage(uint32(i), func([]byte) {}, uint32(usbEndpointInput), make([]byte, 8), []byte{byte(i)})
	}
	// Delivered synchronously: everything has arrived, in order.
	delegate.lock.Lock()
	defer delegate.lock.Unlock()
	if len(delegate.packets) != 200 {
		t.Fatalf("only %d of 200 packets delivered when HandleMessage returned", len(delegate.packets))
	}
	for i, value := range delegate.packets {
		if value != byte(i) {
			t.Fatalf("packet %d delivered at position %d", value, i)
		}
	}
}
