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
    channelId := util.ReadBE[ctapHIDChannelID](buffer)
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
    remaining := len(payload)
    for remaining > 0 {
        packet := []byte{}
        if sequence < 0 {
            // INIT frame
            packet = append(packet, util.ToBE(channelId)...)
            packet = append(packet, util.ToLE(command)...)
            packet = append(packet, util.ToBE(uint16(remaining))...)
        } else {
            // CONT frame
            packet = append(packet, util.ToBE(channelId)...)
            // Use current sequence value in header, then increment
            packet = append(packet, byte(uint8(sequence)))
        }
        // Compute chunk size
        bytesLeft := ctapHIDMaxPacketSize - len(packet)
        chunk := bytesLeft
        if chunk > remaining {
            chunk = remaining
        }
        // Debug log per frame
        if sequence < 0 {
            // INIT frame log
            ctapHIDLogger.Printf("CTAPHID TX INIT: ch=0x%x cmd=%s total=%d chunk=%d\n\n", channelId, ctapHIDCommandDescriptions[command], remaining, chunk)
        } else {
            ctapHIDLogger.Printf("CTAPHID TX CONT: ch=0x%x seq=%d chunk=%d remain=%d\n\n", channelId, sequence, chunk, remaining-chunk)
        }
        // Copy chunk and advance
        packet = append(packet, payload[:chunk]...)
        payload = payload[chunk:]
        remaining -= chunk
        // Increment sequence AFTER using it in the header
        sequence++
        // Pad and append
        packet = util.Pad(packet, ctapHIDMaxPacketSize)
        packets = append(packets, packet)
    }
    return packets
}
