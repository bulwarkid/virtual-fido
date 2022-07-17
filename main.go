package main

import (
	"fmt"
	"net"
)

var device FIDODevice

func handleDeviceRequest(
	conn *net.Conn,
	setup USBSetupPacket,
	transferBuffer []byte) {
	switch setup.BRequest {
	case USB_REQUEST_GET_DESCRIPTOR:
		descriptorType := USBDescriptorType(setup.WValue >> 8)
		descriptorIndex := uint8(setup.WValue & 0xFF)
		descriptor := device.getDescriptor(descriptorType, descriptorIndex)
		copy(transferBuffer, descriptor)
	case USB_REQUEST_SET_CONFIGURATION:
		// No-op since we can't change configuration
		return
	default:
		panic(fmt.Sprintf("Invalid CMD_SUBMIT bRequest: %d", setup.BRequest))
	}
}

func handleInterfaceRequest(conn *net.Conn, setup USBSetupPacket) {
	switch USBHIDRequestType(setup.BRequest) {
	case USB_HID_REQUEST_SET_IDLE:
		// No-op since we are made in software
		return
	default:
		panic(fmt.Sprintf("Invalid USB Interface bRequest: %d", setup.BRequest))
	}
}

func main() {
	device = FIDODevice{}
	server := NewUSBIPServer(&device)
	server.start()
}
