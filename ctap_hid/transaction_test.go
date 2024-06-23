package ctap_hid

import (
	"testing"

	"github.com/bulwarkid/virtual-fido/test"
	"github.com/bulwarkid/virtual-fido/util"
)

func makeHeader(channelId ctapHIDChannelID, command uint8, payloadLength uint16) []byte {
	return util.Concat(util.ToLE(channelId), util.ToLE(command), util.ToBE(payloadLength))
}

func TestSingleMessage(t *testing.T) {
	payload := []byte{1, 2, 3, 4}
	message := util.Concat(makeHeader(1, uint8(ctapHIDCommandCBOR), uint16(len(payload))), payload)
	transaction := newCTAPHIDTransaction(message)
	test.Assert(t, transaction.done, "Transaction is not done")
	result := transaction.result
	test.AssertEqual(t, result.header.ChannelID, 1, "Channel ID is incorrect")
	test.AssertEqual(t, result.header.Command, ctapHIDCommandCBOR, "Command is incorrect")
	test.AssertEqual(t, result.header.PayloadLength, uint16(len(payload)), "Payload length is incorrect")
	test.AssertArrEqual(t, result.payload[:], payload, "Payload is incorrect")
}

func TestMultipleMessages(t *testing.T) {
	var channelId ctapHIDChannelID = 1
	payload := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	payload1 := payload[:4]
	payload2 := payload[4:]
	message := util.Concat(makeHeader(channelId, uint8(ctapHIDCommandCBOR), uint16(len(payload))), payload1)
	transaction := newCTAPHIDTransaction(message)
	test.Assert(t, !transaction.done, "Transaction is done after one message")
	transaction.addMessage(util.Concat(util.ToLE(channelId), []byte{0}, payload2))
	test.Assert(t, transaction.done, "Transaction is not done")
	result := transaction.result
	test.AssertEqual(t, result.header.ChannelID, 1, "Channel ID is incorrect")
	test.AssertEqual(t, result.header.Command, ctapHIDCommandCBOR, "Command is incorrect")
	test.AssertEqual(t, result.header.PayloadLength, uint16(len(payload1)+len(payload2)), "Payload length is incorrect")
	test.AssertArrEqual(t, result.payload, payload, "Payload is incorrect")
}
