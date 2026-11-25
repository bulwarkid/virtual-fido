package ctap_hid

import (
	"github.com/bulwarkid/virtual-fido/util"
)

type ctapHIDChannel struct {
	server      *CTAPHIDServer
	channelId   ctapHIDChannelID
	transaction *ctapHIDTransaction
}

func newCTAPHIDChannel(server *CTAPHIDServer, channelId ctapHIDChannelID) *ctapHIDChannel {
	return &ctapHIDChannel{
		server:      server,
		channelId:   channelId,
		transaction: nil,
	}
}

// handleMessage adds a packet to the channel's current transaction. Called
// with server.lock held.
func (channel *ctapHIDChannel) handleMessage(message []byte) {
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

// handleBroadcastMessage handles INIT and PING on the broadcast channel. They
// are answered even while a command is running, so other programs can still
// allocate a channel.
func (channel *ctapHIDChannel) handleBroadcastMessage(header ctapHIDMessageHeader, payload []byte) {
	switch header.Command {
	case ctapHIDCommandInit:
		if len(payload) != 8 {
			channel.server.sendError(ctapHIDBroadcastChannel, ctapHIDErrorInvalidLength)
			return
		}
		newChannel := channel.server.newChannel()
		response := ctapHIDInitResponse{
			NewChannelID:       newChannel.channelId,
			ProtocolVersion:    2,
			DeviceVersionMajor: 0,
			DeviceVersionMinor: 0,
			DeviceVersionBuild: 1,
			CapabilitiesFlags:  ctapHIDCapabilityCBOR,
		}
		copy(response.Nonce[:], payload)
		ctapHIDLogger.Printf("CTAPHID INIT RESPONSE: %#v\n\n", response)
		channel.server.sendResponse(ctapHIDBroadcastChannel, ctapHIDCommandInit, util.ToLE(response))
	case ctapHIDCommandPing:
		channel.server.sendResponse(ctapHIDBroadcastChannel, ctapHIDCommandPing, payload)
	default:
		ctapHIDLogger.Printf("ERROR: Unsupported CTAPHID broadcast command: %s\n\n", header)
		channel.server.sendError(ctapHIDBroadcastChannel, ctapHIDErrorInvalidCommand)
	}
}

// handleDataMessage handles a complete request on an allocated channel. While
// a command is running, every request other than CANCEL (handled during
// assembly) is rejected with ERR_CHANNEL_BUSY, as hardware authenticators do.
func (channel *ctapHIDChannel) handleDataMessage(header ctapHIDMessageHeader, payload []byte) {
	server := channel.server
	if server.busyChannel != 0 {
		ctapHIDLogger.Printf("CTAPHID: Channel 0x%x busy, rejecting %s\n\n", server.busyChannel, header)
		server.sendError(channel.channelId, ctapHIDErrorChannelBusy)
		return
	}
	switch header.Command {
	case ctapHIDCommandMsg:
		server.runCommand(channel.channelId, header.Command, server.u2fServer, payload)
	case ctapHIDCommandCBOR:
		server.runCommand(channel.channelId, header.Command, server.ctapServer, payload)
	case ctapHIDCommandPing:
		server.sendResponse(channel.channelId, ctapHIDCommandPing, payload)
	default:
		ctapHIDLogger.Printf("ERROR: Unsupported CTAPHID channel command: %s\n\n", header)
		server.sendError(channel.channelId, ctapHIDErrorInvalidCommand)
	}
}
