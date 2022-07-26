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

type CTAPHIDChannel struct{}

type CTAPHIDServer struct {
	ctapServer   *CTAPServer
	u2fServer    *U2FServer
	maxChannelID CTAPHIDChannelID
	channels     map[CTAPHIDChannelID]CTAPHIDChannel
	responses    chan []byte
}

func NewCTAPHIDServer(ctapServer *CTAPServer, u2fServer *U2FServer) *CTAPHIDServer {
	return &CTAPHIDServer{
		ctapServer:   ctapServer,
		u2fServer:    u2fServer,
		maxChannelID: 0,
		channels:     make(map[CTAPHIDChannelID]CTAPHIDChannel),
		responses:    make(chan []byte, 100),
	}
}

func (server *CTAPHIDServer) getResponse() []byte {
	response := <-server.responses
	fmt.Printf("CTAPHID RESPONSE: %#v\n\n", response)
	return response
}

func (server *CTAPHIDServer) handleInputMessage(input io.Reader) {
	var response []byte
	header := readCTAPHIDMessageHeader(input)
	fmt.Printf("CTAPHID MESSAGE: %s\n\n", header)
	if header.ChannelID == CTAPHID_BROADCAST_CHANNEL {
		response = server.handleBroadcastMessage(input, header)
	} else {
		channel, exists := server.channels[header.ChannelID]
		if !exists {
			panic(fmt.Sprintf("Invalid Channel ID: %#v", header))
		}
		response = channel.handleMessage(server, input, header)
	}
	server.responses <- response
}

func (server *CTAPHIDServer) handleBroadcastMessage(input io.Reader, header CTAPHIDMessageHeader) []byte {
	switch header.Command {
	case CTAPHID_COMMAND_INIT:
		nonce := read(input, 8)
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
		server.channels[response.NewChannelID] = CTAPHIDChannel{}
		fmt.Printf("CTAPHID INIT RESPONSE: %#v\n\n", response)
		return newCTAPHIDReponse(CTAPHID_BROADCAST_CHANNEL, CTAPHID_COMMAND_INIT, toLE(response))
	default:
		panic(fmt.Sprintf("Invalid CTAPHID Broadcast command: %#v", header))
	}
}

func (channel *CTAPHIDChannel) handleMessage(ctapServer *CTAPHIDServer, input io.Reader, header CTAPHIDMessageHeader) []byte {
	payload := read(input, uint(header.PayloadLength))
	//fmt.Printf("CTAP MESSAGE PAYLOAD: %#v\n\n", payload)
	switch header.Command {
	case CTAPHID_COMMAND_MSG:
		responsePayload := ctapServer.u2fServer.processU2FMessage(payload)
		return newCTAPHIDReponse(header.ChannelID, CTAPHID_COMMAND_MSG, responsePayload)
	default:
		panic(fmt.Sprintf("Invalid CTAPHID Channel command: %#v", header))
	}
}

func newCTAPHIDReponse(channelId CTAPHIDChannelID, command CTAPHIDCommand, payload []byte) []byte {
	output := new(bytes.Buffer)
	writeCTAPHIDMessageHeader(output, channelId, command, uint16(len(payload)))
	write(output, payload)
	return output.Bytes()
}
