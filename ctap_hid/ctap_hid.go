package ctap_hid

import (
	"bytes"
	"fmt"
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

func (server *CTAPHIDServer) sendResponse(response [][]byte) {
	// Packets should be sequential and continuous per transaction
	server.responsesLock.Lock()
	// ctapHIDLogger.Printf("ADDING MESSAGE: %#v\n\n", response)
	if server.responseHandler != nil {
		for _, packet := range response {
			server.responseHandler(packet)
		}
	}
	server.responsesLock.Unlock()
}

func (server *CTAPHIDServer) HandleMessage(message []byte) {
	buffer := bytes.NewBuffer(message)
	channelId := util.ReadLE[ctapHIDChannelID](buffer)
	channel, exists := server.channels[channelId]
	if !exists {
		response := ctapHidError(channelId, ctapHIDErrorInvalidChannel)
		server.sendResponse(response)
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

type ctapHIDChannel struct {
	server      *CTAPHIDServer
	channelId   ctapHIDChannelID
	messageLock sync.Locker
	transaction *ctapHIDTransaction
}

func newCTAPHIDChannel(server *CTAPHIDServer, channelId ctapHIDChannelID) *ctapHIDChannel {
	return &ctapHIDChannel{
		server:      server,
		channelId:   channelId,
		messageLock: &sync.Mutex{},
		transaction: nil,
	}
}

func (channel *ctapHIDChannel) handleMessage(message []byte) {
	channel.messageLock.Lock()
	if channel.transaction == nil {
		channel.transaction = newCTAPHIDTransaction(message)
	} else {
		channel.transaction.addMessage(message)
	}
	if channel.transaction.done {
		if channel.transaction.errorCode != 0 {
			response := ctapHidError(channel.channelId, channel.transaction.errorCode)
			channel.server.sendResponse(response)
		} else if !channel.transaction.cancelled {
			channel.handleFinalizedMessage(channel.transaction.result.header, channel.transaction.result.payload)
		}
		channel.transaction = nil
	}
	channel.messageLock.Unlock()
}

func (channel *ctapHIDChannel) handleFinalizedMessage(header ctapHIDMessageHeader, payload []byte) {
	// TODO: Handle cancel message
	ctapHIDLogger.Printf("CTAPHID FINALIZED MESSAGE: %s %#v\n\n", header, payload)
	var response [][]byte = nil
	if channel.channelId == ctapHIDBroadcastChannel {
		response = channel.handleBroadcastMessage(header, payload)
	} else {
		response = channel.handleDataMessage(header, payload)
	}
	if response != nil {
		channel.server.sendResponse(response)
	}
}

type ctapHIDInitResponse struct {
	Nonce              [8]byte
	NewChannelID       ctapHIDChannelID
	ProtocolVersion    uint8
	DeviceVersionMajor uint8
	DeviceVersionMinor uint8
	DeviceVersionBuild uint8
	CapabilitiesFlags  ctapHIDCapabilityFlag
}

func (channel *ctapHIDChannel) handleBroadcastMessage(header ctapHIDMessageHeader, payload []byte) [][]byte {
	switch header.Command {
	case ctapHIDCommandInit:
		newChannel := channel.server.newChannel()
		nonce := payload[:8]
		response := ctapHIDInitResponse{
			NewChannelID:       newChannel.channelId,
			ProtocolVersion:    2,
			DeviceVersionMajor: 0,
			DeviceVersionMinor: 0,
			DeviceVersionBuild: 1,
			CapabilitiesFlags:  ctapHIDCapabilityCBOR,
		}
		copy(response.Nonce[:], nonce)
		ctapHIDLogger.Printf("CTAPHID INIT RESPONSE: %#v\n\n", response)
		return createResponsePackets(ctapHIDBroadcastChannel, ctapHIDCommandInit, util.ToLE(response))
	case ctapHIDCommandPing:
		return createResponsePackets(ctapHIDBroadcastChannel, ctapHIDCommandPing, payload)
	default:
		util.Panic(fmt.Sprintf("Invalid CTAPHID Broadcast command: %#v", header))
	}
	return nil
}

func (channel *ctapHIDChannel) handleDataMessage(header ctapHIDMessageHeader, payload []byte) [][]byte {
	switch header.Command {
	case ctapHIDCommandMsg:
		responsePayload := channel.server.u2fServer.HandleMessage(payload)
		ctapHIDLogger.Printf("CTAPHID MSG RESPONSE: %d %#v\n\n", len(responsePayload), responsePayload)
		return createResponsePackets(header.ChannelID, ctapHIDCommandMsg, responsePayload)
	case ctapHIDCommandCBOR:
		stop := util.StartRecurringFunction(keepConnectionAlive(channel.server, channel.channelId, ctapHIDStatusUpneeded), 100)
		responsePayload := channel.server.ctapServer.HandleMessage(payload)
		stop <- 0
		ctapHIDLogger.Printf("CTAPHID CBOR RESPONSE: %#v\n\n", responsePayload)
		return createResponsePackets(header.ChannelID, ctapHIDCommandCBOR, responsePayload)
	case ctapHIDCommandPing:
		return createResponsePackets(header.ChannelID, ctapHIDCommandPing, payload)
	default:
		panic(fmt.Sprintf("Invalid CTAPHID Channel command: %s", header))
	}
}
