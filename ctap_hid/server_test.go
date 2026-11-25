package ctap_hid

import (
	"bytes"
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"github.com/bulwarkid/virtual-fido/test"
	"github.com/bulwarkid/virtual-fido/util"
)

// echoHandler answers every request with a 0x00 status byte and the request.
type echoHandler struct{}

func (echoHandler) HandleMessage(data []byte) []byte { return append([]byte{0}, data...) }

// blockingHandler blocks every request until release is closed, like a
// command waiting for user approval.
type blockingHandler struct {
	started chan struct{}
	release chan struct{}
}

func newBlockingHandler() *blockingHandler {
	return &blockingHandler{started: make(chan struct{}, 10), release: make(chan struct{})}
}

func (handler *blockingHandler) HandleMessage(data []byte) []byte {
	handler.started <- struct{}{}
	<-handler.release
	return []byte{0}
}

type panickingHandler struct{}

func (panickingHandler) HandleMessage(data []byte) []byte { panic("handler failure") }

type hidMessage struct {
	channel ctapHIDChannelID
	command ctapHIDCommand
	payload []byte
}

type pendingMessage struct {
	message hidMessage
	length  int
}

// testHost plays the host side: it frames requests into 64-byte packets and
// reassembles response packets into messages.
type testHost struct {
	server  *CTAPHIDServer
	packets chan []byte
	pending map[ctapHIDChannelID]*pendingMessage
}

func newTestHost(ctapHandler, u2fHandler CTAPHIDClient) *testHost {
	host := &testHost{
		server:  NewCTAPHIDServer(ctapHandler, u2fHandler),
		packets: make(chan []byte, 10000),
		pending: make(map[ctapHIDChannelID]*pendingMessage),
	}
	host.server.SetResponseHandler(func(packet []byte) {
		host.packets <- append([]byte{}, packet...)
	})
	return host
}

func framePackets(channel ctapHIDChannelID, command ctapHIDCommand, payload []byte) [][]byte {
	first := make([]byte, ctapHIDMaxPacketSize)
	copy(first, util.ToLE(channel))
	first[4] = byte(command)
	binary.BigEndian.PutUint16(first[5:], uint16(len(payload)))
	n := copy(first[7:], payload)
	packets := [][]byte{first}
	for sequence := byte(0); n < len(payload); sequence++ {
		packet := make([]byte, ctapHIDMaxPacketSize)
		copy(packet, util.ToLE(channel))
		packet[4] = sequence
		n += copy(packet[5:], payload[n:])
		packets = append(packets, packet)
	}
	return packets
}

// send passes the request's packets to the server back to back and in order,
// as usb_device.go does.
func (host *testHost) send(channel ctapHIDChannelID, command ctapHIDCommand, payload []byte) {
	for _, packet := range framePackets(channel, command, payload) {
		host.server.HandleMessage(packet)
	}
}

// receive returns the next complete message, including keepalives.
func (host *testHost) receive(t *testing.T) hidMessage {
	t.Helper()
	for {
		select {
		case packet := <-host.packets:
			channel := ctapHIDChannelID(binary.LittleEndian.Uint32(packet[:4]))
			var pending *pendingMessage
			if packet[4]&0x80 != 0 {
				pending = &pendingMessage{
					message: hidMessage{channel: channel, command: ctapHIDCommand(packet[4])},
					length:  int(binary.BigEndian.Uint16(packet[5:7])),
				}
				pending.message.payload = append([]byte{}, packet[7:]...)
			} else {
				pending = host.pending[channel]
				if pending == nil {
					t.Fatalf("continuation packet without init packet on channel 0x%x", channel)
				}
				pending.message.payload = append(pending.message.payload, packet[5:]...)
			}
			if len(pending.message.payload) >= pending.length {
				delete(host.pending, channel)
				pending.message.payload = pending.message.payload[:pending.length]
				return pending.message
			}
			host.pending[channel] = pending
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for a response")
		}
	}
}

// receiveResponse returns the next complete message that is not a keepalive.
func (host *testHost) receiveResponse(t *testing.T) hidMessage {
	t.Helper()
	for {
		if message := host.receive(t); message.command != ctapHIDCommandKeepalive {
			return message
		}
	}
}

func (host *testHost) expectNoPacket(t *testing.T, wait time.Duration) {
	t.Helper()
	select {
	case packet := <-host.packets:
		t.Fatalf("unexpected packet: %x", packet[:8])
	case <-time.After(wait):
	}
}

func (host *testHost) openChannel(t *testing.T) ctapHIDChannelID {
	t.Helper()
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	host.send(ctapHIDBroadcastChannel, ctapHIDCommandInit, nonce)
	response := host.receiveResponse(t)
	test.AssertEqual(t, response.command, ctapHIDCommandInit, "INIT not answered")
	test.Assert(t, bytes.Equal(response.payload[:8], nonce), "INIT nonce mismatch")
	return ctapHIDChannelID(binary.LittleEndian.Uint32(response.payload[8:12]))
}

func expectError(t *testing.T, message hidMessage, channel ctapHIDChannelID, code ctapHIDErrorCode) {
	t.Helper()
	test.AssertEqual(t, message.channel, channel, "error on wrong channel")
	test.AssertEqual(t, message.command, ctapHIDCommandError, "expected an error response")
	test.AssertEqual(t, ctapHIDErrorCode(message.payload[0]), code, "unexpected error code")
}

func TestMultiPacketRequestsBackToBack(t *testing.T) {
	host := newTestHost(echoHandler{}, echoHandler{})
	channel := host.openChannel(t)
	for i := 0; i < 200; i++ {
		payload := bytes.Repeat([]byte{byte(i)}, 200) // 4 packets
		host.send(channel, ctapHIDCommandCBOR, payload)
		response := host.receiveResponse(t)
		test.AssertEqual(t, response.command, ctapHIDCommandCBOR, "request was not answered")
		test.Assert(t, bytes.Equal(response.payload[1:], payload), "request payload was reassembled incorrectly")
	}
}

// Run with -race: concurrent callers must not race on the channel map.
func TestConcurrentCallers(t *testing.T) {
	host := newTestHost(echoHandler{}, echoHandler{})
	channel := host.openChannel(t)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			host.send(ctapHIDBroadcastChannel, ctapHIDCommandInit, make([]byte, 8))
		}()
		go func() {
			defer wg.Done()
			host.send(channel, ctapHIDCommandPing, []byte{1})
		}()
	}
	wg.Wait()
}

func TestBusyWhileCommandRuns(t *testing.T) {
	handler := newBlockingHandler()
	host := newTestHost(handler, echoHandler{})
	first := host.openChannel(t)
	second := host.openChannel(t)

	host.send(first, ctapHIDCommandCBOR, []byte{0x04})
	<-handler.started

	// Other requests are answered immediately, without waiting for the command.
	host.send(second, ctapHIDCommandCBOR, []byte{0x04})
	expectError(t, host.receiveResponse(t), second, ctapHIDErrorChannelBusy)
	host.send(first, ctapHIDCommandCBOR, []byte{0x04})
	expectError(t, host.receiveResponse(t), first, ctapHIDErrorChannelBusy)
	host.send(second, ctapHIDCommandPing, []byte{1})
	expectError(t, host.receiveResponse(t), second, ctapHIDErrorChannelBusy)

	// Other programs can still allocate a channel.
	host.openChannel(t)

	// CANCEL is processed (without a response) instead of queueing behind the
	// running command.
	host.send(first, ctapHIDCommandCancel, nil)

	close(handler.release)
	response := host.receiveResponse(t)
	test.AssertEqual(t, response.channel, first, "response on wrong channel")
	test.AssertEqual(t, response.command, ctapHIDCommandCBOR, "command response missing")

	// The device is idle again.
	host.send(second, ctapHIDCommandPing, []byte{9})
	response = host.receiveResponse(t)
	test.AssertEqual(t, response.command, ctapHIDCommandPing, "device still busy after the command finished")
}

func TestKeepaliveStopsBeforeResponse(t *testing.T) {
	handler := newBlockingHandler()
	host := newTestHost(handler, echoHandler{})
	channel := host.openChannel(t)

	host.send(channel, ctapHIDCommandCBOR, []byte{0x04})
	<-handler.started
	keepalive := host.receive(t)
	test.AssertEqual(t, keepalive.command, ctapHIDCommandKeepalive, "no keepalive while the command runs")
	test.AssertEqual(t, keepalive.channel, channel, "keepalive on wrong channel")

	close(handler.release)
	host.receiveResponse(t)
	host.expectNoPacket(t, 3*keepaliveInterval)
}

func TestUnsupportedCommandsDoNotCrash(t *testing.T) {
	host := newTestHost(echoHandler{}, echoHandler{})
	channel := host.openChannel(t)

	for _, command := range []ctapHIDCommand{ctapHIDCommandWink, ctapHIDCommandLock, ctapHIDCommandInit, 0x99} {
		host.send(channel, command, []byte{1})
		expectError(t, host.receiveResponse(t), channel, ctapHIDErrorInvalidCommand)
	}
	host.send(ctapHIDBroadcastChannel, ctapHIDCommandCBOR, []byte{1})
	expectError(t, host.receiveResponse(t), ctapHIDBroadcastChannel, ctapHIDErrorInvalidCommand)
	host.send(ctapHIDBroadcastChannel, ctapHIDCommandInit, []byte{1, 2, 3})
	expectError(t, host.receiveResponse(t), ctapHIDBroadcastChannel, ctapHIDErrorInvalidLength)
}

func TestPanickingCommandReportsError(t *testing.T) {
	host := newTestHost(panickingHandler{}, echoHandler{})
	channel := host.openChannel(t)

	host.send(channel, ctapHIDCommandCBOR, []byte{0x04})
	expectError(t, host.receiveResponse(t), channel, ctapHIDErrorOther)

	host.send(channel, ctapHIDCommandPing, []byte{1})
	test.AssertEqual(t, host.receiveResponse(t).command, ctapHIDCommandPing, "device stuck busy after a panic")
}
