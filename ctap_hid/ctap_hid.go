package ctap_hid

import (
	"bytes"
	"fmt"
	"sync"
	"time"

	"github.com/bulwarkid/virtual-fido/util"
)

var ctapHIDLogger = util.NewLogger("[CTAPHID] ", util.LogLevelDebug)

const ctapHIDStatusUpneeded uint8 = 2

type ctapHIDChannelID uint32

const (
	ctapHIDBroadcastChannel ctapHIDChannelID = 0xFFFFFFFF
)

type ctapHIDCommand uint8

const (
	// Each CTAPHID command has its seventh bit set for easier reading
	ctapHIDCommandMsg       ctapHIDCommand = 0x83
	ctapHIDCommandCBOR      ctapHIDCommand = 0x90
	ctapHIDCommandInit      ctapHIDCommand = 0x86
	ctapHIDCommandPing      ctapHIDCommand = 0x81
	ctapHIDCommandCancel    ctapHIDCommand = 0x91
	ctapHIDCommandError     ctapHIDCommand = 0xBF
	ctapHIDCommandKeepalive ctapHIDCommand = 0xBB
	ctapHIDCommandWink      ctapHIDCommand = 0x88
	ctapHIDCommandLock      ctapHIDCommand = 0x84
)

var ctapHIDCommandDescriptions = map[ctapHIDCommand]string{
	ctapHIDCommandMsg:       "ctapHIDCommandMsg",
	ctapHIDCommandCBOR:      "ctapHIDCommandCBOR",
	ctapHIDCommandInit:      "ctapHIDCommandInit",
	ctapHIDCommandPing:      "ctapHIDCommandPing",
	ctapHIDCommandCancel:    "ctapHIDCommandCancel",
	ctapHIDCommandError:     "ctapHIDCommandError",
	ctapHIDCommandKeepalive: "ctapHIDCommandKeepalive",
	ctapHIDCommandWink:      "ctapHIDCommandWink",
	ctapHIDCommandLock:      "ctapHIDCommandLock",
}

type ctapHIDErrorCode uint8

const (
	ctapHIDErrorInvalidCommand   ctapHIDErrorCode = 0x01
	ctapHIDErrorInvalidParameter ctapHIDErrorCode = 0x02
	ctapHIDErrorInvalidLength    ctapHIDErrorCode = 0x03
	ctapHIDErrorInvalidSequence  ctapHIDErrorCode = 0x04
	ctapHIDErrorMessageTimeout   ctapHIDErrorCode = 0x05
	ctapHIDErrorChannelBusy      ctapHIDErrorCode = 0x06
	ctapHIDErrorLockRequired     ctapHIDErrorCode = 0x0A
	ctapHIDErrorInvalidChannel   ctapHIDErrorCode = 0x0B
	ctapHIDErrorOther             ctapHIDErrorCode = 0x7F
)

var ctapHIDErrorCodeDescriptions = map[ctapHIDErrorCode]string{
	ctapHIDErrorInvalidCommand:   "ctapHIDErrInvalidCommand",
	ctapHIDErrorInvalidParameter: "ctapHIDErrInvalidParameter",
	ctapHIDErrorInvalidLength:    "ctapHIDErrInvalidLength",
	ctapHIDErrorInvalidSequence:  "ctapHIDErrInvalidSequence",
	ctapHIDErrorMessageTimeout:   "ctapHIDErrMessageTimeout",
	ctapHIDErrorChannelBusy:      "ctapHIDErrChannelBusy",
	ctapHIDErrorLockRequired:     "ctapHIDErrLockRequired",
	ctapHIDErrorInvalidChannel:   "ctapHIDErrInvalidChannel",
	ctapHIDErrorOther:             "ctapHIDErrOther",
}

func ctapHidError(channelId ctapHIDChannelID, err ctapHIDErrorCode) [][]byte {
	ctapHIDLogger.Printf("CTAPHID ERROR: %s\n\n", ctapHIDErrorCodeDescriptions[err])
	return createResponsePackets(channelId, ctapHIDCommandError, []byte{byte(err)})
}

type ctapHIDCapabilityFlag uint8

const (
	ctapHIDCapabilityWink ctapHIDCapabilityFlag = 0x1
	ctapHIDCapabilityCBOR ctapHIDCapabilityFlag = 0x4
	ctapHIDCapabilityNoMsg ctapHIDCapabilityFlag = 0x8
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
	if header.ChannelID == ctapHIDBroadcastChannel {
		channelDesc = "CTAPHID_BROADCAST_CHANNEL"
	}
	return fmt.Sprintf("CTAPHIDMessageHeader{ ChannelID: %s, Command: %s, PayloadLength: %d }",
		channelDesc,
		description,
		header.PayloadLength)
}

func (header ctapHIDMessageHeader) isFollowupMessage() bool {
	return (header.Command & (1 << 7)) != 0
}

func newCTAPHIDMessageHeader(ctapHIDChannelID ctapHIDChannelID, command ctapHIDCommand, length uint16) []byte {
	return util.Flatten([][]byte{util.ToLE(ctapHIDChannelID), util.ToLE(command), util.ToBE(length)})
}

const (
	maxPacketSize int = 64
)

type MessageHandler interface {
	HandleMessage(data []byte) []byte
}

type CTAPHIDServer struct {
	ctapServer          MessageHandler
	u2fServer           MessageHandler
	maxChannelID        ctapHIDChannelID
	channels            map[ctapHIDChannelID]*ctapHIDChannel
	responses           chan []byte
	responsesLock       sync.Locker
	waitingForResponses *sync.Map
}

func NewCTAPHIDServer(ctapServer MessageHandler, u2fServer MessageHandler) *CTAPHIDServer {
	server := &CTAPHIDServer{
		ctapServer:          ctapServer,
		u2fServer:           u2fServer,
		maxChannelID:        0,
		channels:            make(map[ctapHIDChannelID]*ctapHIDChannel),
		responses:           make(chan []byte, 100),
		responsesLock:       &sync.Mutex{},
		waitingForResponses: &sync.Map{},
	}
	server.channels[ctapHIDBroadcastChannel] = newCTAPHIDChannel(ctapHIDBroadcastChannel)
	return server
}

func (server *CTAPHIDServer) HasResponse() bool {
	return len(server.responses) > 0
}

func (server *CTAPHIDServer) GetResponse(id uint32, timeout int64) []byte {
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
		// ctapHIDLogger.Printf("CTAPHID RESPONSE: %#v\n\n", response)
		return response
	case <-killSwitch:
		server.waitingForResponses.Delete(id)
		return nil
	case <-timeoutSwitch:
		return []byte{}
	}
}

func (server *CTAPHIDServer) RemoveWaitingRequest(id uint32) bool {
	killSwitch, ok := server.waitingForResponses.Load(id)
	if ok {
		killSwitch.(chan bool) <- true
		return true
	} else {
		return false
	}
}

func (server *CTAPHIDServer) sendResponse(response [][]byte) {
	// Packets should be sequential and continuous per transaction
	server.responsesLock.Lock()
	// ctapHIDLogger.Printf("ADDING MESSAGE: %#v\n\n", response)
	for _, packet := range response {
		server.responses <- packet
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
	channel.handleMessage(server, message)
}

type ctapHIDChannel struct {
	channelId                ctapHIDChannelID
	messageLock              sync.Locker

	inProgressHeader         *ctapHIDMessageHeader
	inProgressSequenceNumber uint8
	inProgressPayload        []byte
}

func newCTAPHIDChannel(channelId ctapHIDChannelID) *ctapHIDChannel {
	return &ctapHIDChannel{
		channelId:         channelId,
		messageLock:       &sync.Mutex{},
		inProgressHeader:  nil,
		inProgressPayload: nil,
	}
}

func (channel *ctapHIDChannel) clearInProgressMessage() {
	channel.inProgressHeader = nil
	channel.inProgressPayload = nil
	channel.inProgressSequenceNumber = 0
}

func (channel *ctapHIDChannel) handleMessage(server *CTAPHIDServer, message []byte) {
	channel.messageLock.Lock()
	if channel.inProgressHeader != nil {
		channel.handleContinuationMessage(server, message)
	} else {
		channel.handleInitializationMessage(server, message)
	}
	channel.messageLock.Unlock()
}

func (channel *ctapHIDChannel) handleInitializationMessage(server *CTAPHIDServer, message []byte) {
	buffer := bytes.NewBuffer(message)
	channelId := util.ReadLE[ctapHIDChannelID](buffer)
	if channelId != channel.channelId {
		// This shouldn't happen, since we should only route this message to the correct channel
		server.sendResponse(ctapHidError(channel.channelId, ctapHIDErrorOther))
		return
	}
	command := util.ReadLE[ctapHIDCommand](buffer)
	if command&(1<<7) == 0 {
		// Non-command (likely a sequence number)
		ctapHIDLogger.Printf("INVALID COMMAND: %x", command)
		server.sendResponse(ctapHidError(channel.channelId, ctapHIDErrorInvalidCommand))
		return
	}
	if command == ctapHIDCommandCancel {
		channel.clearInProgressMessage()
		ctapHIDLogger.Printf("CTAPHID COMMAND: CTAPHID_COMMAND_CANCEL\n\n")
		return // No response to cancel message
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
	} else {
		go channel.handleFinalizedMessage(server, header, payload[:payloadLength])
	}
}

func (channel *ctapHIDChannel) handleContinuationMessage(server *CTAPHIDServer, message []byte) {
	buffer := bytes.NewBuffer(message)
	channelId := util.ReadLE[ctapHIDChannelID](buffer)
	if channelId != channel.channelId {
		// This shouldn't happen, since we should only route this message to the correct channel
		// We should have already checked this by this point.
		server.sendResponse(ctapHidError(channel.channelId, ctapHIDErrorOther))
		return
	}
	val := util.ReadLE[uint8](buffer)
	if val == uint8(ctapHIDCommandCancel) {
		channel.clearInProgressMessage()
		return
	} else if val&(1<<7) != 0 {
		server.sendResponse(ctapHidError(channel.channelId, ctapHIDErrorInvalidSequence))
		return
	}
	sequenceNumber := val
	if sequenceNumber != channel.inProgressSequenceNumber {
		server.sendResponse(ctapHidError(channel.channelId, ctapHIDErrorInvalidSequence))
		return
	}
	payload := buffer.Bytes()
	payloadLeft := int(channel.inProgressHeader.PayloadLength) - len(channel.inProgressPayload)
	if payloadLeft > len(payload) {
		// We need another followup message
		ctapHIDLogger.Printf("CTAPHID: Read %d bytes, Need %d more\n\n", len(payload), payloadLeft-len(payload))
		channel.inProgressPayload = append(channel.inProgressPayload, payload...)
		channel.inProgressSequenceNumber += 1
	} else {
		channel.inProgressPayload = append(channel.inProgressPayload, payload...)
		go channel.handleFinalizedMessage(
			server, *channel.inProgressHeader, channel.inProgressPayload[:channel.inProgressHeader.PayloadLength])
		channel.clearInProgressMessage()
	}
}

func (channel *ctapHIDChannel) handleFinalizedMessage(server *CTAPHIDServer, header ctapHIDMessageHeader, payload []byte) {
	// TODO: Handle cancel message
	ctapHIDLogger.Printf("CTAPHID FINALIZED MESSAGE: %s %#v\n\n", header, payload)
	var response [][]byte = nil
	if channel.channelId == ctapHIDBroadcastChannel {
		response = channel.handleBroadcastMessage(server, header, payload)
	} else {
		response = channel.handleDataMessage(server, header, payload)
	}
	if response != nil {
		server.sendResponse(response)
	}
}

type initReponse struct {
	Nonce              [8]byte
	NewChannelID       ctapHIDChannelID
	ProtocolVersion    uint8
	DeviceVersionMajor uint8
	DeviceVersionMinor uint8
	DeviceVersionBuild uint8
	CapabilitiesFlags  ctapHIDCapabilityFlag
}

func (channel *ctapHIDChannel) handleBroadcastMessage(server *CTAPHIDServer, header ctapHIDMessageHeader, payload []byte) [][]byte {
	switch header.Command {
	case ctapHIDCommandInit:
		nonce := payload[:8]
		response := initReponse{
			NewChannelID:       server.maxChannelID + 1,
			ProtocolVersion:    2,
			DeviceVersionMajor: 0,
			DeviceVersionMinor: 0,
			DeviceVersionBuild: 1,
			CapabilitiesFlags:  ctapHIDCapabilityCBOR,
		}
		copy(response.Nonce[:], nonce)
		server.maxChannelID += 1
		server.channels[response.NewChannelID] = newCTAPHIDChannel(response.NewChannelID)
		ctapHIDLogger.Printf("CTAPHID INIT RESPONSE: %#v\n\n", response)
		return createResponsePackets(ctapHIDBroadcastChannel, ctapHIDCommandInit, util.ToLE(response))
	case ctapHIDCommandPing:
		return createResponsePackets(ctapHIDBroadcastChannel, ctapHIDCommandPing, payload)
	default:
		panic(fmt.Sprintf("Invalid CTAPHID Broadcast command: %#v", header))
	}
}

func (channel *ctapHIDChannel) handleDataMessage(server *CTAPHIDServer, header ctapHIDMessageHeader, payload []byte) [][]byte {
	switch header.Command {
	case ctapHIDCommandMsg:
		responsePayload := server.u2fServer.HandleMessage(payload)
		ctapHIDLogger.Printf("CTAPHID MSG RESPONSE: %d %#v\n\n", len(responsePayload), responsePayload)
		return createResponsePackets(header.ChannelID, ctapHIDCommandMsg, responsePayload)
	case ctapHIDCommandCBOR:
		stop := util.StartRecurringFunction(keepConnectionAlive(server, channel.channelId, ctapHIDStatusUpneeded), 100)
		responsePayload := server.ctapServer.HandleMessage(payload)
		stop <- 0
		ctapHIDLogger.Printf("CTAPHID CBOR RESPONSE: %#v\n\n", responsePayload)
		return createResponsePackets(header.ChannelID, ctapHIDCommandCBOR, responsePayload)
	case ctapHIDCommandPing:
		return createResponsePackets(header.ChannelID, ctapHIDCommandPing, payload)
	default:
		panic(fmt.Sprintf("Invalid CTAPHID Channel command: %s", header))
	}
}

func keepConnectionAlive(server *CTAPHIDServer, channelId ctapHIDChannelID, status uint8) func() {
	return func() {
		response := createResponsePackets(channelId, ctapHIDCommandKeepalive, []byte{byte(status)})
		server.sendResponse(response)
	}
}

func createResponsePackets(channelId ctapHIDChannelID, command ctapHIDCommand, payload []byte) [][]byte {
	packets := [][]byte{}
	sequence := -1
	for len(payload) > 0 {
		packet := []byte{}
		if sequence < 0 {
			packet = append(packet, newCTAPHIDMessageHeader(channelId, command, uint16(len(payload)))...)
		} else {
			packet = append(packet, util.ToLE(channelId)...)
			packet = append(packet, byte(uint8(sequence)))
		}
		sequence++
		bytesLeft := maxPacketSize - len(packet)
		if bytesLeft > len(payload) {
			bytesLeft = len(payload)
		}
		packet = append(packet, payload[:bytesLeft]...)
		payload = payload[bytesLeft:]
		packet = util.Pad(packet, maxPacketSize)
		packets = append(packets, packet)
	}
	return packets
}
