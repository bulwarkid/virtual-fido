package usbip

import (
	"io"
	"net"
	"sync"
	"testing"

	"github.com/bulwarkid/virtual-fido/test"
	"github.com/bulwarkid/virtual-fido/util"
)

type replyDevice struct {
	response []byte
}

func (device *replyDevice) HandleMessage(id uint32, onFinish func(response []byte), endpoint uint32, setupBytes []byte, transferBuffer []byte) {
	onFinish(device.response)
}
func (device *replyDevice) RemoveWaitingRequest(id uint32) bool { return false }
func (device *replyDevice) BusID() string                       { return "2-2" }
func (device *replyDevice) DeviceSummary() USBIPDeviceSummary   { return USBIPDeviceSummary{} }

// submitIn sends an IN transfer of bufferLength bytes to a device that
// answers with response, and returns the reply body and the data after it.
func submitIn(t *testing.T, bufferLength uint32, response []byte) (usbipReturnSubmitBody, []byte) {
	client, server := net.Pipe()
	defer client.Close()
	conn := &usbipConnection{responseMutex: &sync.Mutex{}, conn: server}
	header := usbipMessageHeader{
		Command:        usbipCmdSubmit,
		SequenceNumber: 1,
		Direction:      usbipDirIn,
		Endpoint:       1,
	}
	go func() {
		defer server.Close()
		conn.handleCommandSubmit(&replyDevice{response: response}, header)
	}()
	util.Write(client, util.ToBE(usbipCommandSubmitBody{TransferBufferLength: bufferLength}))
	util.ReadBE[usbipMessageHeader](client)
	body := util.ReadBE[usbipReturnSubmitBody](client)
	data, err := io.ReadAll(client)
	test.Assert(t, err == nil, "Could not read reply data")
	return body, data
}

func TestSubmitInWithoutDataIsEmpty(t *testing.T) {
	body, data := submitIn(t, 64, nil)
	test.AssertEqual(t, body.ActualLength, uint32(0), "Empty transfer reported data")
	test.AssertEqual(t, len(data), 0, "Empty transfer sent data")
}

func TestSubmitInReturnsResponseLength(t *testing.T) {
	response := []byte{1, 2, 3, 4}
	body, data := submitIn(t, 64, response)
	test.AssertEqual(t, body.ActualLength, uint32(len(response)), "Wrong transfer length")
	test.AssertEqual(t, string(data), string(response), "Wrong transfer data")
}
