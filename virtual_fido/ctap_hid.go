package virtual_fido

import (
	"bytes"
	"fmt"
	"sync"
	"time"

	util "github.com/bulwarkid/virtual-fido/virtual_fido/util"
)

var ctapHIDLogger = newLogger("[CTAPHID] ", false)

const ctapHID_STATUS_UPNEEDED uint8 = 2

type ctapHIDChannelID uint32

const (
	ctapHID_BROADCAST_CHANNEL ctapHIDChannelID = 0xFFFFFFFF
)

type ctapHIDCommand uint8

const (
	// Each CTAPHID command has its seventh bit set for easier reading
	ctapHID_COMMAND_MSG       ctapHIDCommand = 0x83
	ctapHID_COMMAND_CBOR      ctapHIDCommand = 0x90
	ctapHID_COMMAND_INIT      ctapHIDCommand = 0x86
	ctapHID_COMMAND_PING      ctapHIDCommand = 0x81
	ctapHID_COMMAND_CANCEL    ctapHIDCommand = 0x91
	ctapHID_COMMAND_ERROR     ctapHIDCommand = 0xBF
	ctapHID_COMMAND_KEEPALIVE ctapHIDCommand = 0xBB
	ctapHID_COMMAND_WINK      ctapHIDCommand = 0x88
	ctapHID_COMMAND_LOCK      ctapHIDCommand = 0x84
)

var ctapHIDCommandDescriptions = map[ctapHIDCommand]string{
	ctapHID_COMMAND_MSG:       "ctapHID_COMMAND_MSG",
	ctapHID_COMMAND_CBOR:      "ctapHID_COMMAND_CBOR",
	ctapHID_COMMAND_INIT:      "ctapHID_COMMAND_INIT",
	ctapHID_COMMAND_PING:      "ctapHID_COMMAND_PING",
	ctapHID_COMMAND_CANCEL:    "ctapHID_COMMAND_CANCEL",
	ctapHID_COMMAND_ERROR:     "ctapHID_COMMAND_ERROR",
	ctapHID_COMMAND_KEEPALIVE: "ctapHID_COMMAND_KEEPALIVE",
	ctapHID_COMMAND_WINK:      "ctapHID_COMMAND_WINK",
	ctapHID_COMMAND_LOCK:      "ctapHID_COMMAND_LOCK",
}

type ctapHIDErrorCode uint8

const (
	ctapHID_ERR_INVALID_COMMAND   ctapHIDErrorCode = 0x01
	ctapHID_ERR_INVALID_PARAMETER ctapHIDErrorCode = 0x02
	ctapHID_ERR_INVALID_LENGTH    ctapHIDErrorCode = 0x03
	ctapHID_ERR_INVALID_SEQUENCE  ctapHIDErrorCode = 0x04
	ctapHID_ERR_MESSAGE_TIMEOUT   ctapHIDErrorCode = 0x05
	ctapHID_ERR_CHANNEL_BUSY      ctapHIDErrorCode = 0x06
	ctapHID_ERR_LOCK_REQUIRED     ctapHIDErrorCode = 0x0A
	ctapHID_ERR_INVALID_CHANNEL   ctapHIDErrorCode = 0x0B
	ctapHID_ERR_OTHER             ctapHIDErrorCode = 0x7F
)

var ctapHIDErrorCodeDescriptions = map[ctapHIDErrorCode]string{
	ctapHID_ERR_INVALID_COMMAND:   "ctapHID_ERR_INVALID_COMMAND",
	ctapHID_ERR_INVALID_PARAMETER: "ctapHID_ERR_INVALID_PARAMETER",
	ctapHID_ERR_INVALID_LENGTH:    "ctapHID_ERR_INVALID_LENGTH",
	ctapHID_ERR_INVALID_SEQUENCE:  "ctapHID_ERR_INVALID_SEQUENCE",
	ctapHID_ERR_MESSAGE_TIMEOUT:   "ctapHID_ERR_MESSAGE_TIMEOUT",
	ctapHID_ERR_CHANNEL_BUSY:      "ctapHID_ERR_CHANNEL_BUSY",
	ctapHID_ERR_LOCK_REQUIRED:     "ctapHID_ERR_LOCK_REQUIRED",
	ctapHID_ERR_INVALID_CHANNEL:   "ctapHID_ERR_INVALID_CHANNEL",
	ctapHID_ERR_OTHER:             "ctapHID_ERR_OTHER",
}

func ctapHidError(channelId ctapHIDChannelID, err ctapHIDErrorCode) [][]byte {
	ctapHIDLogger.Printf("CTAPHID ERROR: %s\n\n", ctapHIDErrorCodeDescriptions[err])
	return createResponsePackets(channelId, ctapHID_COMMAND_ERROR, []byte{byte(err)})
}

type ctapHIDCapabilityFlag uint8

const (
	ctapHID_CAPABILITY_WINK ctapHIDCapabilityFlag = 0x1
	ctapHID_CAPABILITY_CBOR ctapHIDCapabilityFlag = 0x4
	ctapHID_CAPABILITY_NMSG ctapHIDCapabilityFlag = 0x8
)

type ctapHIDMessageHeader struct {
	ChannelID     ctapHIDChannelID
	Command       ctapHIDCommand
	PayloadLength uint16
}

func (header ctapHIDMessageHeader) String() string {
	description, ok := ctapHIDCommandDescriptions[header.Command]
	if !ok {
		description = fmt.Sprintf("0x%x", header.Command)
	}
	channelDesc := fmt.Sprintf("0x%x", header.ChannelID)
	if header.ChannelID == ctapHID_BROADCAST_CHANNEL {
		channelDesc = "ctapHID_BROADCAST_CHANNEL"
	}
	return fmt.Sprintf("ctapHIDMessageHeader{ ChannelID: %s, Command: %s, PayloadLength: %d }",
		channelDesc,
		description,
		header.PayloadLength)
}

func (header ctapHIDMessageHeader) isFollowupMessage() bool {
	return (header.Command & (1 << 7)) != 0
}

func newctapHIDMessageHeader(channelID ctapHIDChannelID, command ctapHIDCommand, length uint16) []byte {
	return util.Flatten([][]byte{util.ToLE(channelID), util.ToLE(command), util.ToBE(length)})
}

type ctapHIDInitReponse struct {
	Nonce              [8]byte
	NewChannelID       ctapHIDChannelID
	ProtocolVersion    uint8
	DeviceVersionMajor uint8
	DeviceVersionMinor uint8
	DeviceVersionBuild uint8
	CapabilitiesFlags  ctapHIDCapabilityFlag
}

const (
	ctapHIDSERVER_MAX_PACKET_SIZE int = 64
)

type ctapHIDServer struct {
	ctapServer          *ctapServer
	u2fServer           *u2fServer
	maxChannelID        ctapHIDChannelID
	channels            map[ctapHIDChannelID]*ctapHIDChannel
	responses           chan []byte
	responsesLock       sync.Locker
	waitingForResponses *sync.Map
}

func newCTAPHIDServer(ctapServer *ctapServer, u2fServer *u2fServer) *ctapHIDServer {
	server := &ctapHIDServer{
		ctapServer:          ctapServer,
		u2fServer:           u2fServer,
		maxChannelID:        0,
		channels:            make(map[ctapHIDChannelID]*ctapHIDChannel),
		responses:           make(chan []byte, 100),
		responsesLock:       &sync.Mutex{},
		waitingForResponses: &sync.Map{},
	}
	server.channels[ctapHID_BROADCAST_CHANNEL] = newCTAPHIDChannel(ctapHID_BROADCAST_CHANNEL)
	return server
}

func (server *ctapHIDServer) getResponse(id uint32, timeout int64) []byte {
	killSwitch := make(chan bool)
	timeoutSwitch := make(chan interface{})
	server.waitingForResponses.Store(id, killSwitch)
	if timeout > 0 {
		go func() {
			time.Sleep(time.Millisecond * time.Duration(timeout))
			timeoutSwitch <- nil
		}()
	}
	select {
	case response := <-server.responses:
		ctapHIDLogger.Printf("CTAPHID RESPONSE: %#v\n\n", response)
		return response
	case <-killSwitch:
		server.waitingForResponses.Delete(id)
		return nil
	case <-timeoutSwitch:
		return []byte{}
	}
}

func (server *ctapHIDServer) removeWaitingRequest(id uint32) bool {
	killSwitch, ok := server.waitingForResponses.Load(id)
	if ok {
		killSwitch.(chan bool) <- true
		return true
	} else {
		return false
	}
}

func (server *ctapHIDServer) sendResponse(response [][]byte) {
	// Packets should be sequential and continuous per transaction
	server.responsesLock.Lock()
	ctapHIDLogger.Printf("ADDING MESSAGE: %#v\n\n", response)
	for _, packet := range response {
		server.responses <- packet
	}
	server.responsesLock.Unlock()
}

func (server *ctapHIDServer) handleMessage(message []byte) {
	buffer := bytes.NewBuffer(message)
	channelId := util.ReadLE[ctapHIDChannelID](buffer)
	channel, exists := server.channels[channelId]
	if !exists {
		response := ctapHidError(channelId, ctapHID_ERR_INVALID_CHANNEL)
		server.sendResponse(response)
		return
	}
	channel.messageLock.Lock()
	channel.handleIntermediateMessage(server, message)
	channel.messageLock.Unlock()
}

type ctapHIDChannel struct {
	channelId                ctapHIDChannelID
	inProgressHeader         *ctapHIDMessageHeader
	inProgressSequenceNumber uint8
	inProgressPayload        []byte
	messageLock              sync.Locker
}

func newCTAPHIDChannel(channelId ctapHIDChannelID) *ctapHIDChannel {
	return &ctapHIDChannel{
		channelId:         channelId,
		inProgressHeader:  nil,
		inProgressPayload: nil,
		messageLock:       &sync.Mutex{},
	}
}

func (channel *ctapHIDChannel) clearInProgressMessage() {
	channel.inProgressHeader = nil
	channel.inProgressPayload = nil
	channel.inProgressSequenceNumber = 0
}

// This function handles CTAPHID transactions, which can be split into multiple USB messages
// After the multiple packets are compiled, then a finalized CTAPHID message is created
func (channel *ctapHIDChannel) handleIntermediateMessage(server *ctapHIDServer, message []byte) {
	buffer := bytes.NewBuffer(message)
	util.ReadLE[ctapHIDChannelID](buffer) // Consume Channel ID
	if channel.inProgressHeader != nil {
		val := util.ReadLE[uint8](buffer)
		if val == uint8(ctapHID_COMMAND_CANCEL) {
			channel.clearInProgressMessage()
			return
		} else if val&(1<<7) != 0 {
			server.sendResponse(ctapHidError(channel.channelId, ctapHID_ERR_INVALID_SEQUENCE))
			return
		}
		sequenceNumber := val
		if sequenceNumber != channel.inProgressSequenceNumber {
			server.sendResponse(ctapHidError(channel.channelId, ctapHID_ERR_INVALID_SEQUENCE))
			return
		}
		payload := buffer.Bytes()
		payloadLeft := int(channel.inProgressHeader.PayloadLength) - len(channel.inProgressPayload)
		if payloadLeft > len(payload) {
			// We need another followup message
			ctapHIDLogger.Printf("CTAPHID: Read %d bytes, Need %d more\n\n", len(payload), payloadLeft-len(payload))
			channel.inProgressPayload = append(channel.inProgressPayload, payload...)
			channel.inProgressSequenceNumber += 1
			return
		} else {
			channel.inProgressPayload = append(channel.inProgressPayload, payload...)
			go channel.handleFinalizedMessage(
				server, *channel.inProgressHeader, channel.inProgressPayload[:channel.inProgressHeader.PayloadLength])
			channel.clearInProgressMessage()
			return
		}
	} else {
		// Command message
		command := util.ReadLE[ctapHIDCommand](buffer)
		if command == ctapHID_COMMAND_CANCEL {
			channel.clearInProgressMessage()
			ctapHIDLogger.Printf("CTAPHID COMMAND: ctapHID_COMMAND_CANCEL\n\n")
			return // No response to cancel message
		}
		if command&(1<<7) == 0 {
			// Non-command (likely a sequence number)
			server.sendResponse(ctapHidError(channel.channelId, ctapHID_ERR_INVALID_COMMAND))
			return
		}
		payloadLength := util.ReadBE[uint16](buffer)
		header := ctapHIDMessageHeader{
			ChannelID:     channel.channelId,
			Command:       command,
			PayloadLength: payloadLength,
		}
		payload := buffer.Bytes()
		if payloadLength > uint16(len(payload)) {
			ctapHIDLogger.Printf("CTAPHID: Read %d bytes, Need %d more\n\n",
				len(payload), int(payloadLength)-len(payload))
			channel.inProgressHeader = &header
			channel.inProgressPayload = payload
			channel.inProgressSequenceNumber = 0
			return
		} else {
			go channel.handleFinalizedMessage(server, header, payload[:payloadLength])
			return
		}
	}
}

func (channel *ctapHIDChannel) handleFinalizedMessage(server *ctapHIDServer, header ctapHIDMessageHeader, payload []byte) {
	// TODO: Handle cancel message
	ctapHIDLogger.Printf("CTAPHID FINALIZED MESSAGE: %s %#v\n\n", header, payload)
	var response [][]byte = nil
	if channel.channelId == ctapHID_BROADCAST_CHANNEL {
		response = channel.handleBroadcastMessage(server, header, payload)
	} else {
		response = channel.handleDataMessage(server, header, payload)
	}
	if response != nil {
		server.sendResponse(response)
	}
}

func (channel *ctapHIDChannel) handleBroadcastMessage(server *ctapHIDServer, header ctapHIDMessageHeader, payload []byte) [][]byte {
	switch header.Command {
	case ctapHID_COMMAND_INIT:
		nonce := payload[:8]
		response := ctapHIDInitReponse{
			NewChannelID:       server.maxChannelID + 1,
			ProtocolVersion:    2,
			DeviceVersionMajor: 0,
			DeviceVersionMinor: 0,
			DeviceVersionBuild: 1,
			CapabilitiesFlags:  ctapHID_CAPABILITY_CBOR,
		}
		copy(response.Nonce[:], nonce)
		server.maxChannelID += 1
		server.channels[response.NewChannelID] = newCTAPHIDChannel(response.NewChannelID)
		ctapHIDLogger.Printf("CTAPHID INIT RESPONSE: %#v\n\n", response)
		return createResponsePackets(ctapHID_BROADCAST_CHANNEL, ctapHID_COMMAND_INIT, util.ToLE(response))
	case ctapHID_COMMAND_PING:
		return createResponsePackets(ctapHID_BROADCAST_CHANNEL, ctapHID_COMMAND_PING, payload)
	default:
		panic(fmt.Sprintf("Invalid CTAPHID Broadcast command: %#v", header))
	}
}

func (channel *ctapHIDChannel) handleDataMessage(server *ctapHIDServer, header ctapHIDMessageHeader, payload []byte) [][]byte {
	switch header.Command {
	case ctapHID_COMMAND_MSG:
		responsePayload := server.u2fServer.handleU2FMessage(payload)
		ctapHIDLogger.Printf("CTAPHID MSG RESPONSE: %#v\n\n", payload)
		return createResponsePackets(header.ChannelID, ctapHID_COMMAND_MSG, responsePayload)
	case ctapHID_COMMAND_CBOR:
		stop := util.StartRecurringFunction(keepConnectionAlive(server, channel.channelId, ctapHID_STATUS_UPNEEDED), 100)
		responsePayload := server.ctapServer.handleMessage(payload)
		stop <- 0
		ctapHIDLogger.Printf("CTAPHID CBOR RESPONSE: %#v\n\n", responsePayload)
		return createResponsePackets(header.ChannelID, ctapHID_COMMAND_CBOR, responsePayload)
	case ctapHID_COMMAND_PING:
		return createResponsePackets(header.ChannelID, ctapHID_COMMAND_PING, payload)
	default:
		panic(fmt.Sprintf("Invalid CTAPHID Channel command: %s", header))
	}
}

func keepConnectionAlive(server *ctapHIDServer, channelId ctapHIDChannelID, status uint8) func() {
	return func() {
		response := createResponsePackets(channelId, ctapHID_COMMAND_KEEPALIVE, []byte{byte(status)})
		server.sendResponse(response)
	}
}

func createResponsePackets(channelId ctapHIDChannelID, command ctapHIDCommand, payload []byte) [][]byte {
	packets := [][]byte{}
	sequence := -1
	for len(payload) > 0 {
		packet := []byte{}
		if sequence < 0 {
			packet = append(packet, newctapHIDMessageHeader(channelId, command, uint16(len(payload)))...)
		} else {
			packet = append(packet, util.ToLE(channelId)...)
			packet = append(packet, byte(uint8(sequence)))
		}
		sequence++
		bytesLeft := ctapHIDSERVER_MAX_PACKET_SIZE - len(packet)
		if bytesLeft > len(payload) {
			bytesLeft = len(payload)
		}
		packet = append(packet, payload[:bytesLeft]...)
		payload = payload[bytesLeft:]
		packet = util.Pad(packet, ctapHIDSERVER_MAX_PACKET_SIZE)
		packets = append(packets, packet)
	}
	return packets
}
