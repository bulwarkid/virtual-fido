package ctap_hid

import (
	"bytes"
	"sync"

	"github.com/bulwarkid/virtual-fido/util"
)

var ctapHIDLogger = util.NewLogger("[CTAPHID] ", util.LogLevelDebug)

type CTAPHIDClient interface {
	HandleMessage(data []byte) []byte
}

type CTAPHIDServer struct {
	ctapServer      CTAPHIDClient
	u2fServer       CTAPHIDClient
	maxChannelID    ctapHIDChannelID
	channels        map[ctapHIDChannelID]*ctapHIDChannel
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

func (server *CTAPHIDServer) HandleMessage(message []byte) {
	buffer := bytes.NewBuffer(message)
	channelId := util.ReadLE[ctapHIDChannelID](buffer)
	channel, exists := server.channels[channelId]
	if !exists {
		server.sendError(channelId, ctapHIDErrorInvalidChannel)
		return
	}
	channel.handleMessage(message)
}

func (server *CTAPHIDServer) newChannel() *ctapHIDChannel {
	channel := newCTAPHIDChannel(server, server.maxChannelID+1)
	server.maxChannelID += 1
	server.channels[channel.channelId] = channel
	return channel
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
