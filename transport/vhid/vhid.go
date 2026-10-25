//go:build darwin && hidvirtual && cgo

package vhid

import (
	"fmt"
	"os"
	"unsafe"

	"github.com/bulwarkid/virtual-fido/ctap_hid"
	"github.com/bulwarkid/virtual-fido/util"
)

/*
#cgo CFLAGS: -DHID_VIRTUAL
#cgo LDFLAGS: -framework CoreHID -framework Foundation -L${SRCDIR}/output -lHIDVirtualDevice
#include <stdlib.h>
#include <stdint.h>
#include "HIDVirtualDevice/HIDVirtualDeviceBridge.h"

// Prototype for Cgo export
void bridgeCallbackWrapper(uint8_t* data, uint64_t length);
*/
import "C"

//export bridgeCallbackWrapper
func bridgeCallbackWrapper(data *byte, length uint64) {
	HIDReceiveReport(data, length)
}

//export HIDReceiveReport
func HIDReceiveReport(dataPointer *byte, length uint64) {
	data := C.GoBytes(unsafe.Pointer(dataPointer), C.int(length))
	fmt.Printf("DEBUG: Received %d bytes report: %x\n", int(length), data)
	os.Stdout.Sync()
	hidLogger.Printf("Received %d bytes report: %x", int(length), data)
	if ctapHIDServer != nil {
		ctapHIDServer.HandleMessage(data)
	}
}

var hidLogger = util.NewLogger("[HID] ", util.LogLevelTrace)

var ctapHIDServer *ctap_hid.CTAPHIDServer
var virtualDevice C.hid_virtual_device_t

var stopChannel = make(chan bool)

type VirtualDevice struct {
	server        *ctap_hid.CTAPHIDServer
	virtualDevice C.hid_virtual_device_t
}

func CreateDevice(server *ctap_hid.CTAPHIDServer, deviceName string) *VirtualDevice {
	server.SetResponseHandler(func(response []byte) {
		if len(response) > 0 {
			fmt.Printf("DEBUG: Sending %d bytes response to HID device: %x\n", len(response), response)
			os.Stdout.Sync()
			C.hid_virtual_device_send_report(
				virtualDevice,
				(*C.uint8_t)(unsafe.Pointer(&response[0])),
				C.size_t(len(response)),
			)
		}
	})
	ctapHIDServer = server

	cDeviceName := C.CString(deviceName)
	defer C.free(unsafe.Pointer(cDeviceName))

	vDevice := C.hid_virtual_device_create(cDeviceName)
	if vDevice == nil {
		hidLogger.Println("Failed to create HIDVirtualDevice")
		return nil
	}
	virtualDevice = vDevice

	C.hid_virtual_device_set_callback(virtualDevice, C.hid_report_callback_t(C.bridgeCallbackWrapper))
	hidLogger.Println("HIDVirtualDevice started successfully")
	return &VirtualDevice{server: server, virtualDevice: virtualDevice}
}

func (d *VirtualDevice) Stop() {
	if virtualDevice != nil {
		hidLogger.Println("Stopping HIDVirtualDevice...")
		C.hid_virtual_device_destroy(virtualDevice)
		virtualDevice = nil
	}
}

func Stop() {
	stopChannel <- true
}

func Start(server *ctap_hid.CTAPHIDServer) {
	device := CreateDevice(server, "Virtual FIDO")
	if device == nil {
		return
	}
	<-stopChannel
	device.Stop()
}
