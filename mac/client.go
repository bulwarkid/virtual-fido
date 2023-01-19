package mac

import (
	"fmt"
	"unsafe"

	"github.com/bulwarkid/virtual-fido/ctap_hid"
)

// #cgo LDFLAGS: -L${SRCDIR}/output -lUSBDriverLib
// #include "client.h"
import "C"

var ctapHIDServer *ctap_hid.CTAPHIDServer

//export receiveDataCallback
func receiveDataCallback(dataPointer unsafe.Pointer, length C.int) (unsafe.Pointer, C.int) {
	fmt.Println("receiveDataCallback()")
	data := C.GoBytes(dataPointer, length)
	fmt.Printf("Bytes: %#v\n",data)
	ctapHIDServer.HandleMessage(data)
	response := ctapHIDServer.GetResponse(0, 10000)
	fmt.Printf("Reponse: %#v\n", response)
	return C.CBytes(response), C.int(len(response))
}

func Start(server *ctap_hid.CTAPHIDServer) {
	ctapHIDServer = server
	C.start_device()
}