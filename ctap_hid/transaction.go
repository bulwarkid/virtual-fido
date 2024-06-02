package ctap_hid

import (
	"bytes"

	"github.com/bulwarkid/virtual-fido/util"
)

// Combines either single messages or multiple messages into a single command header and payload
type ctapHIDTransaction struct {
	done      bool
	header    *ctapHIDMessageHeader
	payload   []byte
	errorCode ctapHIDErrorCode

	inProgressHeader         *ctapHIDMessageHeader
	inProgressSequenceNumber uint8
	inProgressPayload        []byte
}

func newCTAPHIDTransaction(message []byte) *ctapHIDTransaction {
	transaction := ctapHIDTransaction{}
	buffer := bytes.NewBuffer(message)
	channelId := util.ReadLE[ctapHIDChannelID](buffer)
	command := util.ReadLE[ctapHIDCommand](buffer)
	if command&(1<<7) == 0 {
		// Non-command (likely a sequence number)
		ctapHIDLogger.Printf("INVALID COMMAND: %x", command)
		transaction.error(ctapHIDErrorInvalidCommand)
		return &transaction
	}
	if command == ctapHIDCommandCancel {
		ctapHIDLogger.Printf("CTAPHID COMMAND: CTAPHID_COMMAND_CANCEL\n\n")
		transaction.cancel() // No response to cancel message
		return &transaction
	}
	payloadLength := util.ReadBE[uint16](buffer)
	header := ctapHIDMessageHeader{
		ChannelID:     channelId,
		Command:       command,
		PayloadLength: payloadLength,
	}
	payload := buffer.Bytes()
	if payloadLength > uint16(len(payload)) {
		ctapHIDLogger.Printf("CTAPHID: Read %d bytes, Need %d more\n\n",
			len(payload), int(payloadLength)-len(payload))
		transaction.inProgressHeader = &header
		transaction.inProgressPayload = payload
		transaction.inProgressSequenceNumber = 0
	} else {
		transaction.finish(&header, payload[:payloadLength])
	}
	return &transaction
}

func (transaction *ctapHIDTransaction) addMessage(message []byte) {
	if transaction.done {
		ctapHIDLogger.Printf("ERROR - MESSAGE ADDED AFTER SEQUENCE COMPLETED")
		transaction.error(ctapHIDErrorOther)
		return
	}
	buffer := bytes.NewBuffer(message)
	util.ReadLE[ctapHIDChannelID](buffer)
	val := util.ReadLE[uint8](buffer)
	if val == uint8(ctapHIDCommandCancel) {
		transaction.cancel()
		return
	} else if val&(1<<7) != 0 {
		transaction.error(ctapHIDErrorInvalidSequence)
		return
	}
	sequenceNumber := val
	if sequenceNumber != transaction.inProgressSequenceNumber {
		transaction.error(ctapHIDErrorInvalidSequence)
		return
	}
	payload := buffer.Bytes()
	payloadLeft := int(transaction.inProgressHeader.PayloadLength) - len(transaction.inProgressPayload)
	if payloadLeft > len(payload) {
		// We need another followup message
		ctapHIDLogger.Printf("CTAPHID: Read %d bytes, Need %d more\n\n", len(payload), payloadLeft-len(payload))
		transaction.inProgressPayload = append(transaction.inProgressPayload, payload...)
		transaction.inProgressSequenceNumber += 1
	} else {
		transaction.inProgressPayload = append(transaction.inProgressPayload, payload...)
		finalPayload := transaction.inProgressPayload[:transaction.inProgressHeader.PayloadLength]
		transaction.finish(transaction.header, finalPayload)
	}
}

func (transaction *ctapHIDTransaction) finish(header *ctapHIDMessageHeader, payload []byte) {
	transaction.done = true
	transaction.header = header
	transaction.payload = payload
}

func (transaction *ctapHIDTransaction) error(code ctapHIDErrorCode) {
	transaction.done = true
	transaction.errorCode = code
}

func (transaction *ctapHIDTransaction) cancel() {
	transaction.done = true
	transaction.header = nil
	transaction.payload = nil
}
