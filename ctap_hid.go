package main

import (
	"bytes"
	"fmt"
	"io"
)

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
	CTAPHID_COMMAND_ING       CTAPHIDCommand = 0x81
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
	CTAPHID_COMMAND_ING:       "CTAPHID_COMMAND_ING",
	CTAPHID_COMMAND_CANCEL:    "CTAPHID_COMMAND_CANCEL",
	CTAPHID_COMMAND_ERROR:     "CTAPHID_COMMAND_ERROR",
	CTAPHID_COMMAND_KEEPALIVE: "CTAPHID_COMMAND_KEEPALIVE",
	CTAPHID_COMMAND_WINK:      "CTAPHID_COMMAND_WINK",
	CTAPHID_COMMAND_LOCK:      "CTAPHID_COMMAND_LOCK",
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
	return fmt.Sprintf("CTAPHIDMessageHeader{ ChannelID: 0x%x, Command: %s, PayloadLength: %d }",
		header.ChannelID,
		description,
		header.PayloadLength)
}

func (header CTAPHIDMessageHeader) isFollowupMessage() bool {
	return (header.Command & (1 << 7)) != 0
}

func readCTAPHIDMessageHeader(reader io.Reader) CTAPHIDMessageHeader {
	channelID := readLE[CTAPHIDChannelID](reader)
	command := readLE[CTAPHIDCommand](reader)
	payloadLength := readBE[uint16](reader)
	return CTAPHIDMessageHeader{
		ChannelID:     channelID,
		Command:       command,
		PayloadLength: payloadLength,
	}
}

func writeCTAPHIDMessageHeader(writer io.Writer, channelID CTAPHIDChannelID, command CTAPHIDCommand, length uint16) {
	write(writer, toLE(channelID))
	write(writer, toLE(command))
	write(writer, toBE(length))
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

type CTAPHIDChannel struct {
	channelId         CTAPHIDChannelID
	inProgressHeader  *CTAPHIDMessageHeader
	inProgressPayload []byte
}

func NewCTAPHIDChannel(channelId CTAPHIDChannelID) *CTAPHIDChannel {
	return &CTAPHIDChannel{
		channelId:         channelId,
		inProgressHeader:  nil,
		inProgressPayload: nil,
	}
}

const (
	CTAPHIDSERVER_MAX_PACKET_SIZE int = 64
)

type CTAPHIDServer struct {
	ctapServer   *CTAPServer
	u2fServer    *U2FServer
	maxChannelID CTAPHIDChannelID
	channels     map[CTAPHIDChannelID]*CTAPHIDChannel
	responses    chan []byte
}

func NewCTAPHIDServer(ctapServer *CTAPServer, u2fServer *U2FServer) *CTAPHIDServer {
	server := &CTAPHIDServer{
		ctapServer:   ctapServer,
		u2fServer:    u2fServer,
		maxChannelID: 0,
		channels:     make(map[CTAPHIDChannelID]*CTAPHIDChannel),
		responses:    make(chan []byte, 100),
	}
	server.channels[CTAPHID_BROADCAST_CHANNEL] = NewCTAPHIDChannel(CTAPHID_BROADCAST_CHANNEL)
	return server
}

func (server *CTAPHIDServer) getResponse() []byte {
	fmt.Printf("CTAPHID: Getting Response\n\n")
	response := <-server.responses
	fmt.Printf("CTAPHID RESPONSE: %#v\n\n", response)
	return response
}

func (server *CTAPHIDServer) handleMessage(input io.Reader) {
	channelId := readLE[CTAPHIDChannelID](input)
	data := read(input, uint(CTAPHIDSERVER_MAX_PACKET_SIZE)-uint(sizeOf[CTAPHIDChannelID]()))
	channel, exists := server.channels[channelId]
	if !exists {
		panic(fmt.Sprintf("Invalid Channel ID: %d", channelId))
	}
	response := channel.handleMessage(server, data)
	if response != nil {
		for _, packet := range response {
			server.responses <- packet
		}
	}
}

func (channel *CTAPHIDChannel) handleMessage(server *CTAPHIDServer, data []byte) [][]byte {
	if channel.inProgressPayload != nil {
		payloadLeft := int(channel.inProgressHeader.PayloadLength) - len(channel.inProgressPayload)
		payload := data[1:] // Ignore sequence number
		if payloadLeft > len(payload) {
			// We need another followup message
			fmt.Printf("CTAPHID: Read %d bytes, Need %d more\n\n", len(payload), payloadLeft-len(payload))
			channel.inProgressPayload = append(channel.inProgressPayload, payload...)
			return nil
		} else {
			channel.inProgressPayload = append(channel.inProgressPayload, payload...)
			response := channel.handleFinalizedMessage(server, *channel.inProgressHeader, channel.inProgressPayload)
			channel.inProgressHeader = nil
			channel.inProgressPayload = nil
			return response
		}
	} else {
		command := CTAPHIDCommand(data[0])
		payloadLength := uint16(data[1])<<8 + uint16(data[2])
		header := CTAPHIDMessageHeader{
			ChannelID:     channel.channelId,
			Command:       command,
			PayloadLength: payloadLength,
		}
		payload := data[3:]
		if payloadLength > uint16(len(payload)) {
			fmt.Printf("CTAPHID: Read %d bytes, Need %d more\n\n",
				len(payload), int(payloadLength)-len(payload))
			channel.inProgressHeader = &header
			channel.inProgressPayload = payload
			return nil
		} else {
			return channel.handleFinalizedMessage(server, header, payload[:payloadLength])
		}
	}
}

func (channel *CTAPHIDChannel) handleFinalizedMessage(server *CTAPHIDServer, header CTAPHIDMessageHeader, payload []byte) [][]byte {
	fmt.Printf("CTAPHID FINALIZED MESSAGE: %s\n\n", header)
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
		return createReponsePackets(CTAPHID_BROADCAST_CHANNEL, CTAPHID_COMMAND_INIT, toLE(response))
	default:
		panic(fmt.Sprintf("Invalid CTAPHID Broadcast command: %#v", header))
	}
}

func (channel *CTAPHIDChannel) handleDataMessage(server *CTAPHIDServer, header CTAPHIDMessageHeader, payload []byte) [][]byte {
	fmt.Printf("CTAP MESSAGE PAYLOAD: %#v\n\n", payload)
	switch header.Command {
	case CTAPHID_COMMAND_MSG:
		responsePayload := server.u2fServer.handleU2FMessage(payload)
		return createReponsePackets(header.ChannelID, CTAPHID_COMMAND_MSG, responsePayload)
	default:
		panic(fmt.Sprintf("Invalid CTAPHID Channel command: %#v", header))
	}
}

func createReponsePackets(channelId CTAPHIDChannelID, command CTAPHIDCommand, payload []byte) [][]byte {
	packets := [][]byte{}
	sequence := -1
	for len(payload) > 0 {
		output := new(bytes.Buffer)
		if sequence < 0 {
			writeCTAPHIDMessageHeader(output, channelId, command, uint16(len(payload)))
		} else {
			write(output, toLE(channelId))
			write(output, toLE(uint8(sequence)))
		}
		sequence++
		bytesLeft := CTAPHIDSERVER_MAX_PACKET_SIZE - output.Len()
		if bytesLeft > len(payload) {
			bytesLeft = len(payload)
		}
		write(output, payload[:bytesLeft])
		payload = payload[bytesLeft:]
		fill(output, CTAPHIDSERVER_MAX_PACKET_SIZE)
		packets = append(packets, output.Bytes())
	}
	return packets
}
