package main

import "fmt"

type USBSetupPacket struct {
	BmRequestType uint8
	BRequest      USBRequestType
	WValue        uint16
	WIndex        uint16
	WLength       uint16
}

func (setup USBSetupPacket) String() string {
	var requestDescription string
	if setup.recipient() == USB_REQUEST_RECIPIENT_DEVICE {
		requestDescription = deviceRequestDescriptons[setup.BRequest]
	} else {
		requestDescription = interfaceRequestDescriptions[USBHIDRequestType(setup.BRequest)]
	}
	return fmt.Sprintf("USBSetupPacket{ Direction: %s, RequestType: %s, Recipient: %s, BRequest: %s, WValue: 0x%x, WIndex: %d, WLength: %d }",
		requestDirectionDescriptions[setup.direction()],
		requestClassDescriptons[setup.requestClass()],
		requestRecipientDescriptions[setup.recipient()],
		requestDescription,
		setup.WValue,
		setup.WIndex,
		setup.WLength)
}

func (setup *USBSetupPacket) direction() USBDirection {
	return USBDirection((setup.BmRequestType >> 7) & 1)
}

func (setup *USBSetupPacket) requestClass() USBRequestClass {
	return USBRequestClass((setup.BmRequestType >> 4) & 0b11)
}

func (setup *USBSetupPacket) recipient() USBRequestRecipient {
	return USBRequestRecipient(setup.BmRequestType & 0b1111)
}

type USBDeviceDescriptor struct {
	BLength            uint8
	BDescriptorType    USBDescriptorType
	BcdUSB             uint16
	BDeviceClass       uint8
	BDeviceSubclass    uint8
	BDeviceProtocol    uint8
	BMaxPacketSize     uint8
	IdVendor           uint16
	IdProduct          uint16
	BcdDevice          uint16
	IManufacturer      uint8
	IProduct           uint8
	ISerialNumber      uint8
	BNumConfigurations uint8
}

type USBConfigurationDescriptor struct {
	BLength             uint8
	BDescriptorType     USBDescriptorType
	WTotalLength        uint16
	BNumInterfaces      uint8
	BConfigurationValue uint8
	IConfiguration      uint8
	BmAttributes        uint8
	BMaxPower           uint8
}

type USBInterfaceDescriptor struct {
	BLength            uint8
	BDescriptorType    USBDescriptorType
	BInterfaceNumber   uint8
	BAlternateSetting  uint8
	BNumEndpoints      uint8
	BInterfaceClass    uint8
	BInterfaceSubclass uint8
	BInterfaceProtocol uint8
	IInterface         uint8
}

type USBHIDDescriptor struct {
	BLength                 uint8
	BDescriptorType         USBDescriptorType
	BcdHID                  uint16
	BCountryCode            uint8
	BNumDescriptors         uint8
	BClassDescriptorType    USBDescriptorType
	WReportDescriptorLength uint16
}

type USBEndpointDescriptor struct {
	BLength          uint8
	BDescriptorType  USBDescriptorType
	BEndpointAddress uint8
	BmAttributes     uint8
	WMaxPacketSize   uint16
	BInterval        uint8
}

type USBStringDescriptorHeader struct {
	BLength         uint8
	BDescriptorType USBDescriptorType
}

type USBISOPacketDescriptor struct {
	Offset       uint32
	Length       uint32
	ActualLength uint32
	Status       uint32
}
