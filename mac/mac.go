package mac

import (
	"unsafe"

	"github.com/bulwarkid/virtual-fido/ctap_hid"
	"github.com/bulwarkid/virtual-fido/util"
)

// #cgo LDFLAGS: -L${SRCDIR}/output -lUSBDriverLib
// #include "client.h"
import "C"

var macLogger = util.NewLogger("[MAC] ", util.LogLevelTrace)

var ctapHIDServer *ctap_hid.CTAPHIDServer

func sendResponsesLoop() {
	for {
		response := ctapHIDServer.GetResponse(0, 10000)
		if response != nil && len(response) > 0 {
			//macLogger.Printf("Sending Bytes: %#v\n\n", response)
			C.send_data(C.CBytes(response), C.int(len(response)))
		}
	}
}

//export receiveDataCallback
func receiveDataCallback(dataPointer unsafe.Pointer, length C.int) {
	data := C.GoBytes(dataPointer, length)
	//macLogger.Printf("Received Bytes: %d %#v\n\n", length, data)
	ctapHIDServer.HandleMessage(data)
}

func Start(server *ctap_hid.CTAPHIDServer) {
	go sendResponsesLoop()
	ctapHIDServer = server
	C.start_device()
}
