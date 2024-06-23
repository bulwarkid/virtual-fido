package ctap_hid

import (
	"fmt"
)

const (
	ctapHIDMaxPacketSize int = 64
)

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
	ctapHIDErrorOther            ctapHIDErrorCode = 0x7F
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
	ctapHIDErrorOther:            "ctapHIDErrOther",
}

func ctapHidError(channelId ctapHIDChannelID, err ctapHIDErrorCode) [][]byte {
	ctapHIDLogger.Printf("CTAPHID ERROR: %s\n\n", ctapHIDErrorCodeDescriptions[err])
	return createResponsePackets(channelId, ctapHIDCommandError, []byte{byte(err)})
}

type ctapHIDCapabilityFlag uint8

const (
	ctapHIDCapabilityWink  ctapHIDCapabilityFlag = 0x1
	ctapHIDCapabilityCBOR  ctapHIDCapabilityFlag = 0x4
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
