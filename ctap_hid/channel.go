package ctap_hid

import (
	"fmt"
	"sync"

	"github.com/bulwarkid/virtual-fido/util"
)

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
	defer channel.messageLock.Unlock()
	if channel.transaction == nil {
		channel.transaction = newCTAPHIDTransaction(message)
	} else {
		channel.transaction.addMessage(message)
	}
	if channel.transaction.done {
		if channel.transaction.errorCode != 0 {
			channel.server.sendError(channel.channelId, channel.transaction.errorCode)
		} else if !channel.transaction.cancelled {
			channel.handleFinalizedMessage(channel.transaction.result.header, channel.transaction.result.payload)
		}
		channel.transaction = nil
	}
}

func (channel *ctapHIDChannel) handleFinalizedMessage(header ctapHIDMessageHeader, payload []byte) {
	ctapHIDLogger.Printf("CTAPHID FINALIZED MESSAGE: %s %#v\n\n", header, payload)
	if channel.channelId == ctapHIDBroadcastChannel {
		channel.handleBroadcastMessage(header, payload)
	} else {
		channel.handleDataMessage(header, payload)
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

func (channel *ctapHIDChannel) handleBroadcastMessage(header ctapHIDMessageHeader, payload []byte) {
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
		channel.server.sendResponse(ctapHIDBroadcastChannel, ctapHIDCommandInit, util.ToLE(response))
	case ctapHIDCommandPing:
		channel.server.sendResponse(ctapHIDBroadcastChannel, ctapHIDCommandPing, payload)
	default:
		util.Panic(fmt.Sprintf("Invalid CTAPHID Broadcast command: %#v", header))
	}
}

func (channel *ctapHIDChannel) handleDataMessage(header ctapHIDMessageHeader, payload []byte) {
	switch header.Command {
	case ctapHIDCommandMsg:
		responsePayload := channel.server.u2fServer.HandleMessage(payload)
		ctapHIDLogger.Printf("CTAPHID MSG RESPONSE: %d %#v\n\n", len(responsePayload), responsePayload)
		channel.server.sendResponse(header.ChannelID, ctapHIDCommandMsg, responsePayload)
	case ctapHIDCommandCBOR:
		stop := util.StartRecurringFunction(keepConnectionAlive(channel.server, channel.channelId, ctapHIDStatusUpneeded), 50)
		responsePayload := channel.server.ctapServer.HandleMessage(payload)
		stop <- 0
		ctapHIDLogger.Printf("CTAPHID CBOR RESPONSE: %#v\n\n", responsePayload)
		channel.server.sendResponse(header.ChannelID, ctapHIDCommandCBOR, responsePayload)
	case ctapHIDCommandPing:
		channel.server.sendResponse(header.ChannelID, ctapHIDCommandPing, payload)
	default:
		panic(fmt.Sprintf("Invalid CTAPHID Channel command: %s", header))
	}
}

func keepConnectionAlive(server *CTAPHIDServer, channelId ctapHIDChannelID, status byte) func() {
	return func() {
		server.sendResponse(channelId, ctapHIDCommandKeepalive, []byte{status})
	}
}
