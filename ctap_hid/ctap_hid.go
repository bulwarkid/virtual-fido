package ctap_hid

import (
	"bytes"
	"sync"
	"time"

	"github.com/bulwarkid/virtual-fido/util"
)

var ctapHIDLogger = util.NewLogger("[CTAPHID] ", util.LogLevelDebug)

// keepaliveInterval is how often a running CBOR command sends a keepalive.
const keepaliveInterval = 50 * time.Millisecond

type CTAPHIDClient interface {
	HandleMessage(data []byte) []byte
}

type CTAPHIDServer struct {
	ctapServer CTAPHIDClient
	u2fServer  CTAPHIDClient
	// lock guards maxChannelID, channels, busyChannel and the channels'
	// packet assembly state. Packets are assembled while holding it, so they
	// are processed strictly in arrival order; commands run without it.
	lock         sync.Mutex
	maxChannelID ctapHIDChannelID
	channels     map[ctapHIDChannelID]*ctapHIDChannel
	// busyChannel is the channel whose command is running, or 0 (a reserved
	// channel ID) when idle. Only one command runs at a time.
	busyChannel     ctapHIDChannelID
	responsesLock   sync.Locker
	responseHandler func(response []byte)
}

func NewCTAPHIDServer(ctapServer CTAPHIDClient, u2fServer CTAPHIDClient) *CTAPHIDServer {
	server := &CTAPHIDServer{
		ctapServer:      ctapServer,
		u2fServer:       u2fServer,
		maxChannelID:    0,
		channels:        make(map[ctapHIDChannelID]*ctapHIDChannel),
		responsesLock:   &sync.Mutex{},
		responseHandler: nil,
	}
	server.channels[ctapHIDBroadcastChannel] = newCTAPHIDChannel(server, ctapHIDBroadcastChannel)
	return server
}

func (server *CTAPHIDServer) SetResponseHandler(handler func(response []byte)) {
	server.responseHandler = handler
}

func (server *CTAPHIDServer) sendResponsePackets(packets [][]byte) {
	// Packets should be sequential and continuous per transaction
	server.responsesLock.Lock()
	defer server.responsesLock.Unlock()
	// ctapHIDLogger.Printf("ADDING MESSAGE: %#v\n\n", response)
	if server.responseHandler != nil {
		for _, packet := range packets {
			server.responseHandler(packet)
		}
	}
}

// HandleMessage processes one HID packet. Callers must pass packets in the
// order they were received. It returns quickly: commands run in the
// background, so packets such as CANCEL or requests on other channels are
// still processed while a command waits for user approval.
func (server *CTAPHIDServer) HandleMessage(message []byte) {
	server.lock.Lock()
	defer server.lock.Unlock()
	buffer := bytes.NewBuffer(message)
	channelId := util.ReadLE[ctapHIDChannelID](buffer)
	channel, exists := server.channels[channelId]
	if !exists {
		server.sendError(channelId, ctapHIDErrorInvalidChannel)
		return
	}
	channel.handleMessage(message)
}

// newChannel allocates a channel. Called with server.lock held.
func (server *CTAPHIDServer) newChannel() *ctapHIDChannel {
	channel := newCTAPHIDChannel(server, server.maxChannelID+1)
	server.maxChannelID += 1
	server.channels[channel.channelId] = channel
	return channel
}

// runCommand executes a MSG or CBOR command in the background and sends its
// response. Called with server.lock held, after checking that no other
// command is running.
func (server *CTAPHIDServer) runCommand(channelId ctapHIDChannelID, command ctapHIDCommand, handler CTAPHIDClient, payload []byte) {
	server.busyChannel = channelId
	go func() {
		response, ok := server.executeCommand(channelId, command, handler, payload)
		// Become idle before responding, so the host's next request is not
		// rejected as busy.
		server.lock.Lock()
		server.busyChannel = 0
		server.lock.Unlock()
		if ok {
			ctapHIDLogger.Printf("CTAPHID %s RESPONSE: %#v\n\n", ctapHIDCommandDescriptions[command], response)
			server.sendResponse(channelId, command, response)
		} else {
			server.sendError(channelId, ctapHIDErrorOther)
		}
	}()
}

// executeCommand runs the handler, sending keepalives for CBOR commands until
// it returns. A panicking handler is reported as a failure instead of taking
// down the device, and the server does not stay busy.
func (server *CTAPHIDServer) executeCommand(channelId ctapHIDChannelID, command ctapHIDCommand, handler CTAPHIDClient, payload []byte) (response []byte, ok bool) {
	if command == ctapHIDCommandCBOR {
		stopKeepalive := server.startKeepalive(channelId)
		defer stopKeepalive()
	}
	defer func() {
		if err := recover(); err != nil {
			ctapHIDLogger.Printf("ERROR: %s handler panicked: %v\n\n", ctapHIDCommandDescriptions[command], err)
			response, ok = nil, false
		}
	}()
	return handler.HandleMessage(payload), true
}

// startKeepalive sends keepalives on the channel until the returned function
// is called. That function waits until no further keepalive can be sent, so
// none follows the command's response.
func (server *CTAPHIDServer) startKeepalive(channelId ctapHIDChannelID) func() {
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(keepaliveInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				server.sendResponse(channelId, ctapHIDCommandKeepalive, []byte{ctapHIDStatusUpneeded})
			case <-done:
				return
			}
		}
	}()
	return func() {
		close(done)
		<-stopped
	}
}

func (server *CTAPHIDServer) sendResponse(channelID ctapHIDChannelID, command ctapHIDCommand, payload []byte) {
	packets := createResponsePackets(channelID, command, payload)
	server.sendResponsePackets(packets)
}

func (server *CTAPHIDServer) sendError(channelID ctapHIDChannelID, errorCode ctapHIDErrorCode) {
	response := ctapHidError(channelID, errorCode)
	server.sendResponsePackets(response)
}

func createResponsePackets(channelId ctapHIDChannelID, command ctapHIDCommand, payload []byte) [][]byte {
	packets := [][]byte{}
	sequence := -1
	for len(payload) > 0 {
		packet := []byte{}
		if sequence < 0 {
			packet = append(packet, util.ToLE(channelId)...)
			packet = append(packet, util.ToLE(command)...)
			packet = append(packet, util.ToBE(uint16(len(payload)))...)
		} else {
			packet = append(packet, util.ToLE(channelId)...)
			packet = append(packet, byte(uint8(sequence)))
		}
		sequence++
		bytesLeft := ctapHIDMaxPacketSize - len(packet)
		if bytesLeft > len(payload) {
			bytesLeft = len(payload)
		}
		packet = append(packet, payload[:bytesLeft]...)
		payload = payload[bytesLeft:]
		packet = util.Pad(packet, ctapHIDMaxPacketSize)
		packets = append(packets, packet)
	}
	return packets
}
