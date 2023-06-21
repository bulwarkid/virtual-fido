package ctap_hid

import (
	"bytes"
	"testing"

	"github.com/bulwarkid/virtual-fido/crypto"
	"github.com/bulwarkid/virtual-fido/util"
)

type dummyHandler struct{}

func (server *dummyHandler) HandleMessage(data []byte) []byte {
	return nil
}

func TestOpenChannel(t *testing.T) {
	dummyCTAP := dummyHandler{}
	dummyU2F := dummyHandler{}
	server := NewCTAPHIDServer(&dummyCTAP, &dummyU2F)
	initCmd := byte((1 << 7) | 0x06)
	nonce := crypto.RandomBytes(8)
	initializationMessage := util.Flatten(
		[][]byte{
			util.ToLE[uint32](0xFFFFFFFF),
			{initCmd},
			util.ToBE[uint16](8),
			nonce})
	server.HandleMessage(initializationMessage)
	response := server.GetResponse(0, 1000)
	correctResponse := util.Flatten([][]byte{
		util.ToLE[uint32](0xFFFFFFFF),
		{initCmd},
		util.ToBE[uint16](17),
		nonce,
		util.ToLE[uint32](1),
		{2, 0, 0, 1, 0b00000100},
	})
	correctResponse = util.Pad(correctResponse, 64)
	if !bytes.Equal(response, correctResponse) {
		t.Errorf("Initialization message returned incorrect response: %#v vs %#v", response, correctResponse)
	}
}
