package ctap_hid

import (
	"bytes"

	"github.com/bulwarkid/virtual-fido/util"
)

type transactionResult struct {
	header         ctapHIDMessageHeader
	sequenceNumber uint8
	payload        []byte
}

// Combines either single messages or multiple messages into a single command header and payload
type ctapHIDTransaction struct {
	done      bool
	cancelled bool
	errorCode ctapHIDErrorCode
	result    *transactionResult
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
		transaction.cancel() // No response to cancel message
		return &transaction
	}
	payloadLength := util.ReadBE[uint16](buffer)
	result := transactionResult{
		header: ctapHIDMessageHeader{
			ChannelID:     channelId,
			Command:       command,
			PayloadLength: payloadLength,
		},
		sequenceNumber: 0,
		payload:        buffer.Bytes(),
	}
	transaction.result = &result
	if len(transaction.result.payload) >= int(transaction.result.header.PayloadLength) {
		transaction.result.payload = transaction.result.payload[:transaction.result.header.PayloadLength]
		transaction.finish()
	} else {
		ctapHIDLogger.Printf("CTAPHID: Read %d bytes, Need %d more\n\n",
			len(transaction.result.payload),
			int(payloadLength)-len(transaction.result.payload))
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
	channelId := util.ReadLE[ctapHIDChannelID](buffer)
	if channelId != transaction.result.header.ChannelID {
		transaction.error(ctapHIDErrorInvalidChannel)
		return
	}
	sequenceNumber := util.ReadLE[uint8](buffer)
	if sequenceNumber == uint8(ctapHIDCommandCancel) {
		transaction.cancel()
		return
	} else if sequenceNumber&(1<<7) != 0 {
		transaction.error(ctapHIDErrorInvalidSequence)
		return
	} else if sequenceNumber != transaction.result.sequenceNumber {
		transaction.error(ctapHIDErrorInvalidSequence)
		return
	}
	payload := buffer.Bytes()
	transaction.result.payload = append(transaction.result.payload, payload...)
	if len(transaction.result.payload) >= int(transaction.result.header.PayloadLength) {
		transaction.result.payload = transaction.result.payload[:transaction.result.header.PayloadLength]
		transaction.finish()
	} else {
		// We need another followup message
		ctapHIDLogger.Printf("CTAPHID: Read %d bytes, Need %d more\n\n",
			len(transaction.result.payload),
			int(transaction.result.header.PayloadLength)-len(transaction.result.payload))
		transaction.result.sequenceNumber += 1
	}
}

func (transaction *ctapHIDTransaction) finish() {
	transaction.done = true
}

func (transaction *ctapHIDTransaction) error(code ctapHIDErrorCode) {
	ctapHIDLogger.Printf("CTAPHID TRANSACTION ERROR: %v\n\n", ctapHIDErrorCodeDescriptions[code])
	transaction.done = true
	transaction.errorCode = code
	transaction.result = nil
}

func (transaction *ctapHIDTransaction) cancel() {
	ctapHIDLogger.Printf("CTAPHID COMMAND: CTAPHID_COMMAND_CANCEL\n\n")
	transaction.done = true
	transaction.cancelled = true
	transaction.result = nil
}
