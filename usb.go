package main

import "fmt"

const (
	USB_REQUEST_GET_STATUS        = 0
	USB_REQUEST_CLEAR_FEATURE     = 1
	USB_REQUEST_SET_FEATURE       = 3
	USB_REQUEST_SET_ADDRESS       = 5
	USB_REQUEST_GET_DESCRIPTOR    = 6
	USB_REQUEST_SET_DESCRIPTOR    = 7
	USB_REQUEST_GET_CONFIGURATION = 8
	USB_REQUEST_SET_CONFIGURATION = 9
	USB_REQUEST_GET_INTERFACE     = 10
	USB_REQUEST_SET_INTERFACE     = 11
	USB_REQUEST_SYNCH_FRAME       = 12

	USB_DESCRIPTOR_DEVICE                    = 1
	USB_DESCRIPTOR_CONFIGURATION             = 2
	USB_DESCRIPTOR_STRING                    = 3
	USB_DESCRIPTOR_INTERFACE                 = 4
	USB_DESCRIPTOR_ENDPOINT                  = 5
	USB_DESCRIPTOR_DEVICE_QUALIFIER          = 6
	USB_DESCRIPTOR_OTHER_SPEED_CONFIGURATION = 7
	USB_DESCRIPTOR_INTERFACE_POWER           = 8
	USB_DESCRIPTOR_HID                       = 33
	USB_DESCRIPTOR_HID_REPORT                = 34

	USB_CONFIG_ATTR_BASE          = 0b10000000
	USB_CONFIG_ATTR_SELF_POWERED  = 0b01000000
	USB_CONFIG_ATTR_REMOTE_WAKEUP = 0b00100000

	USB_INTERFACE_CLASS_HID = 3

	USB_HOST_TO_DEVICE = 0
	USB_DEVICE_TO_HOST = 1

	USB_REQUEST_TYPE_STANDARD = 0
	USB_REQUEST_TYPE_CLASS    = 1
	USB_REQUEST_TYPE_VENDOR   = 2
	USB_REQUEST_TYPE_RESERVED = 3

	USB_REQUEST_RECIPIENT_DEVICE    = 0
	USB_REQUEST_RECIPIENT_INTERFACE = 1
	USB_REQUEST_RECIPIENT_ENDPOINT  = 2
	USB_REQUEST_RECIPIENT_OTHER     = 3

	USB_HID_REQUEST_GET_REPORT   = 1
	USB_HID_REQUEST_GET_IDLE     = 2
	USB_HID_REQUEST_GET_PROTOCOL = 3
	USB_HID_REQUEST_SET_REPORT   = 9
	USB_HID_REQUEST_SET_IDLE     = 10
	USB_HID_REQUEST_SET_PROTOCOL = 11
)

var deviceRequestDescriptons = map[uint8]string{
	USB_REQUEST_GET_STATUS:        "USB_REQUEST_GET_STATUS",
	USB_REQUEST_CLEAR_FEATURE:     "USB_REQUEST_CLEAR_FEATURE",
	USB_REQUEST_SET_FEATURE:       "USB_REQUEST_SET_FEATURE",
	USB_REQUEST_SET_ADDRESS:       "USB_REQUEST_SET_ADDRESS",
	USB_REQUEST_GET_DESCRIPTOR:    "USB_REQUEST_GET_DESCRIPTOR",
	USB_REQUEST_SET_DESCRIPTOR:    "USB_REQUEST_SET_DESCRIPTOR",
	USB_REQUEST_GET_CONFIGURATION: "USB_REQUEST_GET_CONFIGURATION",
	USB_REQUEST_SET_CONFIGURATION: "USB_REQUEST_SET_CONFIGURATION",
	USB_REQUEST_GET_INTERFACE:     "USB_REQUEST_GET_INTERFACE",
	USB_REQUEST_SET_INTERFACE:     "USB_REQUEST_SET_INTERFACE",
	USB_REQUEST_SYNCH_FRAME:       "USB_REQUEST_SYNCH_FRAME",
}

var interfaceRequestDescriptions = map[uint8]string{
	USB_HID_REQUEST_GET_REPORT:   "USB_HID_REQUEST_GET_REPORT",
	USB_HID_REQUEST_GET_IDLE:     "USB_HID_REQUEST_GET_IDLE",
	USB_HID_REQUEST_GET_PROTOCOL: "USB_HID_REQUEST_GET_PROTOCOL",
	USB_HID_REQUEST_SET_REPORT:   "USB_HID_REQUEST_SET_REPORT",
	USB_HID_REQUEST_SET_IDLE:     "USB_HID_REQUEST_SET_IDLE",
	USB_HID_REQUEST_SET_PROTOCOL: "USB_HID_REQUEST_SET_PROTOCOL",
}

var requestDirectionDescriptions = map[uint8]string{
	USB_HOST_TO_DEVICE: "USB_HOST_TO_DEVICE",
	USB_DEVICE_TO_HOST: "USB_DEVICE_TO_HOST",
}

var requestClassDescriptons = map[uint8]string{
	USB_REQUEST_TYPE_STANDARD: "USB_REQUEST_TYPE_STANDARD",
	USB_REQUEST_TYPE_CLASS:    "USB_REQUEST_TYPE_CLASS",
	USB_REQUEST_TYPE_VENDOR:   "USB_REQUEST_TYPE_VENDOR",
	USB_REQUEST_TYPE_RESERVED: "USB_REQUEST_TYPE_RESERVED",
}

var requestRecipientDescriptions = map[uint8]string{
	USB_REQUEST_RECIPIENT_DEVICE:    "USB_REQUEST_RECIPIENT_DEVICE",
	USB_REQUEST_RECIPIENT_INTERFACE: "USB_REQUEST_RECIPIENT_INTERFACE",
	USB_REQUEST_RECIPIENT_ENDPOINT:  "USB_REQUEST_RECIPIENT_ENDPOINT",
	USB_REQUEST_RECIPIENT_OTHER:     "USB_REQUEST_RECIPIENT_OTHER",
}

type USBSetupPacket struct {
	BmRequestType uint8
	BRequest      uint8
	WValue        uint16
	WIndex        uint16
	WLength       uint16
}

func (setup USBSetupPacket) String() string {
	var requestDescription string
	if setup.recipient() == USB_REQUEST_RECIPIENT_DEVICE {
		requestDescription = deviceRequestDescriptons[setup.BRequest]
	} else {
		requestDescription = interfaceRequestDescriptions[setup.BRequest]
	}
	return fmt.Sprintf("USBSetupPacket{ Direction: %s, RequestType: %s, Recipient: %s, BRequest: %s, WValue: 0x%x, WIndex: %d, WLength: %d }",
		requestDirectionDescriptions[setup.direction()],
		requestClassDescriptons[setup.requestType()],
		requestRecipientDescriptions[setup.recipient()],
		requestDescription,
		setup.WValue,
		setup.WIndex,
		setup.WLength)
}

func (setup *USBSetupPacket) direction() uint8 {
	return (setup.BmRequestType >> 7) & 1
}

func (setup *USBSetupPacket) requestType() uint8 {
	return (setup.BmRequestType >> 4) & 0b11
}

func (setup *USBSetupPacket) recipient() uint8 {
	return setup.BmRequestType & 0b1111
}

type USBDeviceDescriptor struct {
	BLength            uint8
	BDescriptorType    uint8
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
	BDescriptorType     uint8
	WTotalLength        uint16
	BNumInterfaces      uint8
	BConfigurationValue uint8
	IConfiguration      uint8
	BmAttributes        uint8
	BMaxPower           uint8
}

type USBInterfaceDescriptor struct {
	BLength            uint8
	BDescriptorType    uint8
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
	BDescriptorType         uint8
	BcdHID                  uint16
	BCountryCode            uint8
	BNumDescriptors         uint8
	BClassDescriptorType    uint8
	WReportDescriptorLength uint16
}

type USBEndpointDescriptor struct {
	BLength          uint8
	BDescriptorType  uint8
	BEndpointAddress uint8
	BmAttributes     uint8
	WMaxPacketSize   uint16
	BInterval        uint8
}

type USBStringDescriptorHeader struct {
	BLength         uint8
	BDescriptorType uint8
}

type USBISOPacketDescriptor struct {
	Offset       uint32
	Length       uint32
	ActualLength uint32
	Status       uint32
}
