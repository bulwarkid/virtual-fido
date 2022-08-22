package virtual_fido

import (
	"bytes"
	"fmt"
	"sync"
)

const CTAPHID_STATUS_UPNEEDED uint8 = 2

type CTAPHIDChannelID uint32

const (
	CTAPHID_BROADCAST_CHANNEL CTAPHIDChannelID = 0xFFFFFFFF
)

type CTAPHIDCommand uint8

const (
	// Each CTAPHID command has its seventh bit set for easier reading
	CTAPHID_COMMAND_MSG       CTAPHIDCommand = 0x83
	CTAPHID_COMMAND_CBOR      CTAPHIDCommand = 0x90
	CTAPHID_COMMAND_INIT      CTAPHIDCommand = 0x86
	CTAPHID_COMMAND_PING      CTAPHIDCommand = 0x81
	CTAPHID_COMMAND_CANCEL    CTAPHIDCommand = 0x91
	CTAPHID_COMMAND_ERROR     CTAPHIDCommand = 0xBF
	CTAPHID_COMMAND_KEEPALIVE CTAPHIDCommand = 0xBB
	CTAPHID_COMMAND_WINK      CTAPHIDCommand = 0x88
	CTAPHID_COMMAND_LOCK      CTAPHIDCommand = 0x84
)

var ctapHIDCommandDescriptions = map[CTAPHIDCommand]string{
	CTAPHID_COMMAND_MSG:       "CTAPHID_COMMAND_MSG",
	CTAPHID_COMMAND_CBOR:      "CTAPHID_COMMAND_CBOR",
	CTAPHID_COMMAND_INIT:      "CTAPHID_COMMAND_INIT",
	CTAPHID_COMMAND_PING:      "CTAPHID_COMMAND_PING",
	CTAPHID_COMMAND_CANCEL:    "CTAPHID_COMMAND_CANCEL",
	CTAPHID_COMMAND_ERROR:     "CTAPHID_COMMAND_ERROR",
	CTAPHID_COMMAND_KEEPALIVE: "CTAPHID_COMMAND_KEEPALIVE",
	CTAPHID_COMMAND_WINK:      "CTAPHID_COMMAND_WINK",
	CTAPHID_COMMAND_LOCK:      "CTAPHID_COMMAND_LOCK",
}

type CTAPHIDErrorCode uint8

const (
	CTAPHID_ERR_INVALID_COMMAND   CTAPHIDErrorCode = 0x01
	CTAPHID_ERR_INVALID_PARAMETER CTAPHIDErrorCode = 0x02
	CTAPHID_ERR_INVALID_LENGTH    CTAPHIDErrorCode = 0x03
	CTAPHID_ERR_INVALID_SEQUENCE  CTAPHIDErrorCode = 0x04
	CTAPHID_ERR_MESSAGE_TIMEOUT   CTAPHIDErrorCode = 0x05
	CTAPHID_ERR_CHANNEL_BUSY      CTAPHIDErrorCode = 0x06
	CTAPHID_ERR_LOCK_REQUIRED     CTAPHIDErrorCode = 0x0A
	CTAPHID_ERR_INVALID_CHANNEL   CTAPHIDErrorCode = 0x0B
	CTAPHID_ERR_OTHER             CTAPHIDErrorCode = 0x7F
)

var ctapHIDErrorCodeDescriptions = map[CTAPHIDErrorCode]string{
	CTAPHID_ERR_INVALID_COMMAND:   "CTAPHID_ERR_INVALID_COMMAND",
	CTAPHID_ERR_INVALID_PARAMETER: "CTAPHID_ERR_INVALID_PARAMETER",
	CTAPHID_ERR_INVALID_LENGTH:    "CTAPHID_ERR_INVALID_LENGTH",
	CTAPHID_ERR_INVALID_SEQUENCE:  "CTAPHID_ERR_INVALID_SEQUENCE",
	CTAPHID_ERR_MESSAGE_TIMEOUT:   "CTAPHID_ERR_MESSAGE_TIMEOUT",
	CTAPHID_ERR_CHANNEL_BUSY:      "CTAPHID_ERR_CHANNEL_BUSY",
	CTAPHID_ERR_LOCK_REQUIRED:     "CTAPHID_ERR_LOCK_REQUIRED",
	CTAPHID_ERR_INVALID_CHANNEL:   "CTAPHID_ERR_INVALID_CHANNEL",
	CTAPHID_ERR_OTHER:             "CTAPHID_ERR_OTHER",
}

func ctapHidError(channelId CTAPHIDChannelID, err CTAPHIDErrorCode) [][]byte {
	fmt.Printf("CTAPHID ERROR: %s\n\n", ctapHIDErrorCodeDescriptions[err])
	return createResponsePackets(channelId, CTAPHID_COMMAND_ERROR, []byte{byte(err)})
}

type CTAPHIDCapabilityFlag uint8

const (
	CTAPHID_CAPABILITY_WINK CTAPHIDCapabilityFlag = 0x1
	CTAPHID_CAPABILITY_CBOR CTAPHIDCapabilityFlag = 0x4
	CTAPHID_CAPABILITY_NMSG CTAPHIDCapabilityFlag = 0x8
)

type CTAPHIDMessageHeader struct {
	ChannelID     CTAPHIDChannelID
	Command       CTAPHIDCommand
	PayloadLength uint16
}

func (header CTAPHIDMessageHeader) String() string {
	description, ok := ctapHIDCommandDescriptions[header.Command]
	if !ok {
		description = fmt.Sprintf("0x%x", header.Command)
	}
	channelDesc := fmt.Sprintf("0x%x", header.ChannelID)
	if header.ChannelID == CTAPHID_BROADCAST_CHANNEL {
		channelDesc = "CTAPHID_BROADCAST_CHANNEL"
	}
	return fmt.Sprintf("CTAPHIDMessageHeader{ ChannelID: %s, Command: %s, PayloadLength: %d }",
		channelDesc,
		description,
		header.PayloadLength)
}

func (header CTAPHIDMessageHeader) isFollowupMessage() bool {
	return (header.Command & (1 << 7)) != 0
}

func newCTAPHIDMessageHeader(channelID CTAPHIDChannelID, command CTAPHIDCommand, length uint16) []byte {
	return flatten([][]byte{toLE(channelID), toLE(command), toBE(length)})
}

type CTAPHIDInitReponse struct {
	Nonce              [8]byte
	NewChannelID       CTAPHIDChannelID
	ProtocolVersion    uint8
	DeviceVersionMajor uint8
	DeviceVersionMinor uint8
	DeviceVersionBuild uint8
	CapabilitiesFlags  uint8
}

const (
	CTAPHIDSERVER_MAX_PACKET_SIZE int = 64
)

type CTAPHIDServer struct {
	ctapServer          *CTAPServer
	u2fServer           *U2FServer
	maxChannelID        CTAPHIDChannelID
	channels            map[CTAPHIDChannelID]*CTAPHIDChannel
	responses           chan []byte
	waitingForResponses *sync.Map
}

func newCTAPHIDServer(ctapServer *CTAPServer, u2fServer *U2FServer) *CTAPHIDServer {
	server := &CTAPHIDServer{
		ctapServer:          ctapServer,
		u2fServer:           u2fServer,
		maxChannelID:        0,
		channels:            make(map[CTAPHIDChannelID]*CTAPHIDChannel),
		responses:           make(chan []byte, 100),
		waitingForResponses: &sync.Map{},
	}
	server.channels[CTAPHID_BROADCAST_CHANNEL] = NewCTAPHIDChannel(CTAPHID_BROADCAST_CHANNEL)
	return server
}

func (server *CTAPHIDServer) getResponse(id uint32) []byte {
	//fmt.Printf("CTAPHID: Getting Response\n\n")
	killSwitch := make(chan bool)
	server.waitingForResponses.Store(id, killSwitch)
	select {
	case response := <-server.responses:
		//fmt.Printf("CTAPHID RESPONSE: %#v\n\n", response)
		return response
	case <-killSwitch:
		server.waitingForResponses.Delete(id)
		return nil
	}
}

func (server *CTAPHIDServer) removeWaitingRequest(id uint32) bool {
	killSwitch, ok := server.waitingForResponses.Load(id)
	if ok {
		killSwitch.(chan bool) <- true
		return true
	} else {
		return false
	}
}

func (server *CTAPHIDServer) sendResponse(response [][]byte) {
	for _, packet := range response {
		server.responses <- packet
	}
}

func (server *CTAPHIDServer) handleMessage(message []byte) {
	buffer := bytes.NewBuffer(message)
	channelId := readLE[CTAPHIDChannelID](buffer)
	channel, exists := server.channels[channelId]
	if !exists {
		response := ctapHidError(channelId, CTAPHID_ERR_INVALID_CHANNEL)
		server.sendResponse(response)
		return
	}
	response := channel.handleMessage(server, message)
	if response != nil {
		server.sendResponse(response)
	}
}

type CTAPHIDChannel struct {
	channelId                CTAPHIDChannelID
	inProgressHeader         *CTAPHIDMessageHeader
	inProgressSequenceNumber uint8
	inProgressPayload        []byte
}

func NewCTAPHIDChannel(channelId CTAPHIDChannelID) *CTAPHIDChannel {
	return &CTAPHIDChannel{
		channelId:         channelId,
		inProgressHeader:  nil,
		inProgressPayload: nil,
	}
}

func (channel *CTAPHIDChannel) clearInProgressMessage() {
	channel.inProgressHeader = nil
	channel.inProgressPayload = nil
	channel.inProgressSequenceNumber = 0
}

func (channel *CTAPHIDChannel) handleMessage(server *CTAPHIDServer, message []byte) [][]byte {
	buffer := bytes.NewBuffer(message)
	readLE[CTAPHIDChannelID](buffer) // Consume Channel ID
	if channel.inProgressHeader != nil {
		val := readLE[uint8](buffer)
		if val == uint8(CTAPHID_COMMAND_CANCEL) {
			channel.clearInProgressMessage()
			return nil
		} else if val&(1<<7) != 0 {
			return ctapHidError(channel.channelId, CTAPHID_ERR_INVALID_SEQUENCE)
		}
		sequenceNumber := val
		if sequenceNumber != channel.inProgressSequenceNumber {
			return ctapHidError(channel.channelId, CTAPHID_ERR_INVALID_SEQUENCE)
		}
		payload := buffer.Bytes()
		payloadLeft := int(channel.inProgressHeader.PayloadLength) - len(channel.inProgressPayload)
		if payloadLeft > len(payload) {
			// We need another followup message
			//fmt.Printf("CTAPHID: Read %d bytes, Need %d more\n\n", len(payload), payloadLeft-len(payload))
			channel.inProgressPayload = append(channel.inProgressPayload, payload...)
			channel.inProgressSequenceNumber += 1
			return nil
		} else {
			channel.inProgressPayload = append(channel.inProgressPayload, payload...)
			response := channel.handleFinalizedMessage(
				server, *channel.inProgressHeader, channel.inProgressPayload[:channel.inProgressHeader.PayloadLength])
			channel.clearInProgressMessage()
			return response
		}
	} else {
		// Command message
		command := readLE[CTAPHIDCommand](buffer)
		if command == CTAPHID_COMMAND_CANCEL {
			channel.clearInProgressMessage()
			fmt.Printf("CTAPHID COMMAND: CTAPHID_COMMAND_CANCEL\n\n")
			return nil // No response to cancel message
		}
		if command&(1<<7) == 0 {
			// Non-command (likely a sequence number)
			return ctapHidError(channel.channelId, CTAPHID_ERR_INVALID_COMMAND)
		}
		payloadLength := readBE[uint16](buffer)
		header := CTAPHIDMessageHeader{
			ChannelID:     channel.channelId,
			Command:       command,
			PayloadLength: payloadLength,
		}
		payload := buffer.Bytes()
		if payloadLength > uint16(len(payload)) {
			//fmt.Printf("CTAPHID: Read %d bytes, Need %d more\n\n",
			//	len(payload), int(payloadLength)-len(payload))
			channel.inProgressHeader = &header
			channel.inProgressPayload = payload
			channel.inProgressSequenceNumber = 0
			return nil
		} else {
			return channel.handleFinalizedMessage(server, header, payload[:payloadLength])
		}
	}
}

func (channel *CTAPHIDChannel) handleFinalizedMessage(server *CTAPHIDServer, header CTAPHIDMessageHeader, payload []byte) [][]byte {
	// TODO: Handle cancel message
	fmt.Printf("CTAPHID FINALIZED MESSAGE: %s %#v\n\n", header, payload)
	if channel.channelId == CTAPHID_BROADCAST_CHANNEL {
		return channel.handleBroadcastMessage(server, header, payload)
	} else {
		return channel.handleDataMessage(server, header, payload)
	}
}

func (channel *CTAPHIDChannel) handleBroadcastMessage(server *CTAPHIDServer, header CTAPHIDMessageHeader, payload []byte) [][]byte {
	switch header.Command {
	case CTAPHID_COMMAND_INIT:
		nonce := payload[:8]
		response := CTAPHIDInitReponse{
			NewChannelID:       server.maxChannelID + 1,
			ProtocolVersion:    2,
			DeviceVersionMajor: 0,
			DeviceVersionMinor: 0,
			DeviceVersionBuild: 1,
			CapabilitiesFlags:  0,
		}
		copy(response.Nonce[:], nonce)
		server.maxChannelID += 1
		server.channels[response.NewChannelID] = NewCTAPHIDChannel(response.NewChannelID)
		fmt.Printf("CTAPHID INIT RESPONSE: %#v\n\n", response)
		return createResponsePackets(CTAPHID_BROADCAST_CHANNEL, CTAPHID_COMMAND_INIT, toLE(response))
	case CTAPHID_COMMAND_PING:
		return createResponsePackets(CTAPHID_BROADCAST_CHANNEL, CTAPHID_COMMAND_PING, payload)
	default:
		panic(fmt.Sprintf("Invalid CTAPHID Broadcast command: %#v", header))
	}
}

func (channel *CTAPHIDChannel) handleDataMessage(server *CTAPHIDServer, header CTAPHIDMessageHeader, payload []byte) [][]byte {
	switch header.Command {
	case CTAPHID_COMMAND_MSG:
		responsePayload := server.u2fServer.handleU2FMessage(payload)
		fmt.Printf("CTAPHID MSG RESPONSE: %#v\n\n", payload)
		return createResponsePackets(header.ChannelID, CTAPHID_COMMAND_MSG, responsePayload)
	case CTAPHID_COMMAND_CBOR:
		stop := startRecurringFunction(keepConnectionAlive(server, channel.channelId, CTAPHID_STATUS_UPNEEDED), 100)
		responsePayload := server.ctapServer.handleMessage(payload)
		stop <- 0
		fmt.Printf("CTAPHID CBOR RESPONSE: %#v\n\n", responsePayload)
		return createResponsePackets(header.ChannelID, CTAPHID_COMMAND_CBOR, responsePayload)
	case CTAPHID_COMMAND_PING:
		return createResponsePackets(header.ChannelID, CTAPHID_COMMAND_PING, payload)
	default:
		panic(fmt.Sprintf("Invalid CTAPHID Channel command: %s", header))
	}
}

func keepConnectionAlive(server *CTAPHIDServer, channelId CTAPHIDChannelID, status uint8) func() {
	return func() {
		response := createResponsePackets(channelId, CTAPHID_COMMAND_KEEPALIVE, []byte{byte(status)})
		server.sendResponse(response)
	}
}

func createResponsePackets(channelId CTAPHIDChannelID, command CTAPHIDCommand, payload []byte) [][]byte {
	packets := [][]byte{}
	sequence := -1
	for len(payload) > 0 {
		packet := []byte{}
		if sequence < 0 {
			packet = append(packet, newCTAPHIDMessageHeader(channelId, command, uint16(len(payload)))...)
		} else {
			packet = append(packet, toLE(channelId)...)
			packet = append(packet, byte(uint8(sequence)))
		}
		sequence++
		bytesLeft := CTAPHIDSERVER_MAX_PACKET_SIZE - len(packet)
		if bytesLeft > len(payload) {
			bytesLeft = len(payload)
		}
		packet = append(packet, payload[:bytesLeft]...)
		payload = payload[bytesLeft:]
		packet = pad(packet, CTAPHIDSERVER_MAX_PACKET_SIZE)
		packets = append(packets, packet)
	}
	return packets
}
