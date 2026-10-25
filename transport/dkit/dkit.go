//go:build darwin && !hidvirtual && cgo

package dkit

import (
	"unsafe"

	"github.com/bulwarkid/virtual-fido/ctap_hid"
	"github.com/bulwarkid/virtual-fido/util"
)

// #cgo LDFLAGS: -L${SRCDIR}/output -lUSBDriverLib
// #include <stdlib.h>
// #include "client.h"
import "C"

var macLogger = util.NewLogger("[MAC] ", util.LogLevelTrace)

var ctapHIDServer *ctap_hid.CTAPHIDServer

func handleResponse(response []byte) {
	if len(response) > 0 {
		macLogger.Printf("Sending Bytes: %#v\n\n", response)
		cBytes := C.CBytes(response)
		defer C.free(cBytes)
		C.send_data(cBytes, C.int(len(response)))
	}
}

//export receiveDataCallback
func receiveDataCallback(dataPointer unsafe.Pointer, length C.int) {
	data := C.GoBytes(dataPointer, length)
	macLogger.Printf("Received Bytes: %d %#v\n\n", length, data)
	ctapHIDServer.HandleMessage(data)
}

func Stop() {
	C.stop_device()
}

func Start(server *ctap_hid.CTAPHIDServer) {
	server.SetResponseHandler(handleResponse)
	ctapHIDServer = server
	C.start_device()
}
