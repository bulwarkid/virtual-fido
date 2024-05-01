package usb

import (
	"bytes"
	"testing"

	"github.com/bulwarkid/virtual-fido/test"
	"github.com/bulwarkid/virtual-fido/util"
)

type dummyUSBDeviceDelegate struct {
	transferBuffer []byte
}

func (delegate *dummyUSBDeviceDelegate) HandleMessage(transferBuffer []byte) {
	delegate.transferBuffer = transferBuffer
}
func (delegate *dummyUSBDeviceDelegate) SetResponseHandler(handler func(response []byte)) {}

func TestGetDescriptor(t *testing.T) {
	delegate := dummyUSBDeviceDelegate{}
	device := NewUSBDevice(&delegate)
	var response []byte = nil
	setResponse := func(other []byte) {
		response = other
	}
	var setup usbSetupPacket
	setup.setDirection(usbHostToDevice)
	setup.setRequestClass(usbRequestClassStandard)
	setup.setRecipient(usbRequestRecipientDevice)
	setup.BRequest = usbRequestGetDescriptor
	setup.WValue = (uint16(usbDescriptorDevice) << 8)
	setup.WLength = 64
	setupBytes := util.ToLE(setup)
	device.HandleMessage(0, setResponse, 0, setupBytes, []byte{})
	test.AssertNotNil(t, response, "Response is nil")
	deviceDescriptor := util.ReadLE[usbDeviceDescriptor](bytes.NewBuffer(response))
	test.AssertEqual(t, int(deviceDescriptor.BLength), len(response), "Incorrect descriptor length")
	test.AssertEqual(t, deviceDescriptor.BDescriptorType, usbDescriptorDevice, "Incorrect descriptor type")
	test.AssertEqual(t, deviceDescriptor.BcdUSB, 0x110, "Invalid bcdUSB")
	test.AssertEqual(t, deviceDescriptor.BNumConfigurations, 1, "Invalid number configurations")
}

func TestGetConfiguration(t *testing.T) {
	delegate := dummyUSBDeviceDelegate{}
	device := NewUSBDevice(&delegate)
	var response []byte = nil
	setResponse := func(other []byte) {
		response = other
	}
	var setup usbSetupPacket
	setup.setDirection(usbHostToDevice)
	setup.setRequestClass(usbRequestClassStandard)
	setup.setRecipient(usbRequestRecipientDevice)
	setup.BRequest = usbRequestGetDescriptor
	setup.WValue = (uint16(usbDescriptorConfiguration) << 8)
	setup.WLength = 64
	setupBytes := util.ToLE(setup)
	device.HandleMessage(0, setResponse, 0, setupBytes, []byte{})
	test.AssertNotNil(t, response, "Response is nil")
	responseBuffer := bytes.NewBuffer(response)
	configuration := util.ReadLE[usbConfigurationDescriptor](responseBuffer)
	test.AssertEqual(t, configuration.BLength, util.SizeOf[usbConfigurationDescriptor](), "BLength incorrect")
	test.AssertEqual(t, int(configuration.WTotalLength), len(response), "WTotalLength incorrect")
	test.AssertEqual(t, configuration.BDescriptorType, usbDescriptorConfiguration, "Incorrect descriptor type")
	test.AssertEqual(t, configuration.BNumInterfaces, 1, "Num interfaces incorrect")
	interfaceDesc := util.ReadLE[usbInterfaceDescriptor](responseBuffer)
	test.AssertEqual(t, interfaceDesc.BLength, util.SizeOf[usbInterfaceDescriptor](), "BLength incorrect")
	test.AssertEqual(t, interfaceDesc.BNumEndpoints, 2, "Incorrect num endpoints")
	hidDescriptor := util.ReadLE[usbHIDDescriptor](responseBuffer)
	test.AssertEqual(t, hidDescriptor.BLength, util.SizeOf[usbHIDDescriptor](), "BLength incorrect")
	test.AssertEqual(t, hidDescriptor.BDescriptorType, usbDescriptorHID, "Descriptor type wrong")
	test.AssertEqual(t, hidDescriptor.BCountryCode, usbHIDCountryCodeNone, "Invalid country code")
	for i := 0; i < int(interfaceDesc.BNumEndpoints); i++ {
		endpoint := util.ReadLE[usbEndpointDescriptor](responseBuffer)
		test.AssertEqual(t, endpoint.BDescriptorType, usbDescriptorEndpoint, "Endpoint type incorrect")
	}
}

func TestGetStringDescriptor(t *testing.T) {
	delegate := dummyUSBDeviceDelegate{}
	device := NewUSBDevice(&delegate)
	var response []byte = nil
	setResponse := func(other []byte) {
		response = other
	}
	// Right now there are 5 string descriptors; we just need to check if we can generally access them
	for i := 0; i < 5; i++ {
		var setup usbSetupPacket
		setup.setDirection(usbHostToDevice)
		setup.setRequestClass(usbRequestClassStandard)
		setup.setRecipient(usbRequestRecipientDevice)
		setup.BRequest = usbRequestGetDescriptor
		setup.WValue = (uint16(usbDescriptorString) << 8 | uint16(i))
		setup.WLength = 64
		setupBytes := util.ToLE(setup)
		device.HandleMessage(0, setResponse, 0, setupBytes, []byte{})
		stringBytes := append(response, 0)
		test.AssertNotEqual(t, util.CStringToString(stringBytes), "", "Invalid string")
	}
}

func TestGetHIDReport(t *testing.T) {
	delegate := dummyUSBDeviceDelegate{}
	device := NewUSBDevice(&delegate)
	var response []byte = nil
	setResponse := func(other []byte) {
		response = other
	}
	var setup usbSetupPacket
	setup.setDirection(usbHostToDevice)
	setup.setRequestClass(usbRequestClassStandard)
	setup.setRecipient(usbRequestRecipientInterface)
	setup.BRequest = usbRequestType(usbHIDRequestGetDescriptor)
	setup.WValue = (uint16(usbDescriptorHIDReport) << 8)
	setup.WLength = 64
	setupBytes := util.ToLE(setup)
	device.HandleMessage(0, setResponse, 0, setupBytes, []byte{})
	test.AssertNotNil(t, response, "Nil HID report")
	test.AssertNotEqual(t, len(response), 0, "Empty HID report")
}

func TestBusID(t *testing.T) {
	delegate := dummyUSBDeviceDelegate{}
	device := NewUSBDevice(&delegate)
	if device.BusID() != "2-2" {
		t.Fatalf("Bus ID is not 2-2")
	}
}

func TestDeviceSummary(t *testing.T) {
	delegate := dummyUSBDeviceDelegate{}
	device := NewUSBDevice(&delegate)
	// Check a few fields in the summary to make sure they are correct
	summary := device.DeviceSummary()
	if summary.Header.Busnum != 2 || 
		summary.Header.Devnum != 2 || 
		util.CStringToString(summary.Header.BusID[:]) != "2-2" || 
		util.CStringToString(summary.Header.Path[:]) != "/device/0" {
		t.Fatalf("Device summary incorrect")
	}
}