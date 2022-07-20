package main

import (
	"bytes"
	"container/list"
	"fmt"
	"io"
)

type CTAPHIDChannelID uint32

const (
	CTAPHID_BROADCAST_CHANNEL CTAPHIDChannelID = 0xFFFFFFFF
)

type CTAPHIDCommand uint8

const (
	CTAPHID_COMMAND_MSG       CTAPHIDCommand = 0x03
	CTAPHID_COMMAND_CBOR      CTAPHIDCommand = 0x10
	CTAPHID_COMMAND_INIT      CTAPHIDCommand = 0x06
	CTAPHID_COMMAND_ING       CTAPHIDCommand = 0x01
	CTAPHID_COMMAND_CANCEL    CTAPHIDCommand = 0x11
	CTAPHID_COMMAND_ERROR     CTAPHIDCommand = 0x3F
	CTAPHID_COMMAND_KEEPALIVE CTAPHIDCommand = 0x3B
	CTAPHID_COMMAND_WINK      CTAPHIDCommand = 0x08
	CTAPHID_COMMAND_LOCK      CTAPHIDCommand = 0x04
)

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
	maxChannelID CTAPHIDChannelID
	channels     map[CTAPHIDChannelID]CTAPHIDChannel
	responses    *list.List
}

func NewCTAPHIDServer() *CTAPHIDServer {
	return &CTAPHIDServer{
		maxChannelID: 0,
		channels:     make(map[CTAPHIDChannelID]CTAPHIDChannel),
		responses:    list.New(),
	}
}

func (server *CTAPHIDServer) getResponse() []byte {
	response := server.responses.Front()
	if response != nil {
		server.responses.Remove(response)
		return response.Value.([]byte)
	} else {
		return nil
	}
}

func (server *CTAPHIDServer) handleInputMessage(input io.Reader) {
	response := new(bytes.Buffer)
	header := readCTAPHIDMessageHeader(input)
	if header.ChannelID == CTAPHID_BROADCAST_CHANNEL {
		server.handleBroadcastMessage(input, response, header)
	} else {
		channel, exists := server.channels[header.ChannelID]
		if !exists {
			panic(fmt.Sprintf("Invalid Channel ID: %#v", header))
		}
		channel.handleMessage(input, response, header)
	}
	server.responses.PushBack(response.Bytes())
}

func (server *CTAPHIDServer) handleBroadcastMessage(input io.Reader, output io.Writer, header CTAPHIDMessageHeader) {
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
		writeCTAPHIDMessageHeader(output, CTAPHID_BROADCAST_CHANNEL, CTAPHID_COMMAND_INIT, 17)
		write(output, toLE(response))
	default:
		panic(fmt.Sprintf("Invalid CTAPHID Broadcast command: %#v", header))
	}
}

func (channel *CTAPHIDChannel) handleMessage(input io.Reader, output io.Writer, header CTAPHIDMessageHeader) {
	fmt.Printf("CTAPHID Message: %#v\n", header)
}
