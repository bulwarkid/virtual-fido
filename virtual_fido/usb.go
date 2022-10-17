package virtual_fido

import "fmt"

type usbRequestType uint8

const (
	usb_REQUEST_GET_STATUS        usbRequestType = 0
	usb_REQUEST_CLEAR_FEATURE     usbRequestType = 1
	usb_REQUEST_SET_FEATURE       usbRequestType = 3
	usb_REQUEST_SET_ADDRESS       usbRequestType = 5
	usb_REQUEST_GET_DESCRIPTOR    usbRequestType = 6
	usb_REQUEST_SET_DESCRIPTOR    usbRequestType = 7
	usb_REQUEST_GET_CONFIGURATION usbRequestType = 8
	usb_REQUEST_SET_CONFIGURATION usbRequestType = 9
	usb_REQUEST_GET_INTERFACE     usbRequestType = 10
	usb_REQUEST_SET_INTERFACE     usbRequestType = 11
	usb_REQUEST_SYNCH_FRAME       usbRequestType = 12
)

var deviceRequestDescriptons = map[usbRequestType]string{
	usb_REQUEST_GET_STATUS:        "usb_REQUEST_GET_STATUS",
	usb_REQUEST_CLEAR_FEATURE:     "usb_REQUEST_CLEAR_FEATURE",
	usb_REQUEST_SET_FEATURE:       "usb_REQUEST_SET_FEATURE",
	usb_REQUEST_SET_ADDRESS:       "usb_REQUEST_SET_ADDRESS",
	usb_REQUEST_GET_DESCRIPTOR:    "usb_REQUEST_GET_DESCRIPTOR",
	usb_REQUEST_SET_DESCRIPTOR:    "usb_REQUEST_SET_DESCRIPTOR",
	usb_REQUEST_GET_CONFIGURATION: "usb_REQUEST_GET_CONFIGURATION",
	usb_REQUEST_SET_CONFIGURATION: "usb_REQUEST_SET_CONFIGURATION",
	usb_REQUEST_GET_INTERFACE:     "usb_REQUEST_GET_INTERFACE",
	usb_REQUEST_SET_INTERFACE:     "usb_REQUEST_SET_INTERFACE",
	usb_REQUEST_SYNCH_FRAME:       "usb_REQUEST_SYNCH_FRAME",
}

type usbDescriptorType uint8

const (
	usb_DESCRIPTOR_DEVICE                    usbDescriptorType = 1
	usb_DESCRIPTOR_CONFIGURATION             usbDescriptorType = 2
	usb_DESCRIPTOR_STRING                    usbDescriptorType = 3
	usb_DESCRIPTOR_INTERFACE                 usbDescriptorType = 4
	usb_DESCRIPTOR_ENDPOINT                  usbDescriptorType = 5
	usb_DESCRIPTOR_DEVICE_QUALIFIER          usbDescriptorType = 6
	usb_DESCRIPTOR_OTHER_SPEED_CONFIGURATION usbDescriptorType = 7
	usb_DESCRIPTOR_INTERFACE_POWER           usbDescriptorType = 8
	usb_DESCRIPTOR_HID                       usbDescriptorType = 33
	usb_DESCRIPTOR_HID_REPORT                usbDescriptorType = 34
)

var descriptorTypeDescriptions = map[usbDescriptorType]string{
	usb_DESCRIPTOR_DEVICE:                    "usb_DESCRIPTOR_DEVICE",
	usb_DESCRIPTOR_CONFIGURATION:             "usb_DESCRIPTOR_CONFIGURATION",
	usb_DESCRIPTOR_STRING:                    "usb_DESCRIPTOR_STRING",
	usb_DESCRIPTOR_INTERFACE:                 "usb_DESCRIPTOR_INTERFACE",
	usb_DESCRIPTOR_ENDPOINT:                  "usb_DESCRIPTOR_ENDPOINT",
	usb_DESCRIPTOR_DEVICE_QUALIFIER:          "usb_DESCRIPTOR_DEVICE_QUALIFIER",
	usb_DESCRIPTOR_OTHER_SPEED_CONFIGURATION: "usb_DESCRIPTOR_OTHER_SPEED_CONFIGURATION",
	usb_DESCRIPTOR_INTERFACE_POWER:           "usb_DESCRIPTOR_INTERFACE_POWER",
	usb_DESCRIPTOR_HID:                       "usb_DESCRIPTOR_HID",
	usb_DESCRIPTOR_HID_REPORT:                "usb_DESCRIPTOR_HID_REPORT",
}

type usbHIDRequestType uint8

const (
	usb_HID_REQUEST_GET_REPORT     usbHIDRequestType = 1
	usb_HID_REQUEST_GET_IDLE       usbHIDRequestType = 2
	usb_HID_REQUEST_GET_PROTOCOL   usbHIDRequestType = 3
	usb_HID_REQUEST_GET_DESCRIPTOR usbHIDRequestType = 6
	usb_HID_REQUEST_SET_DESCRIPTOR usbHIDRequestType = 7
	usb_HID_REQUEST_SET_REPORT     usbHIDRequestType = 9
	usb_HID_REQUEST_SET_IDLE       usbHIDRequestType = 10
	usb_HID_REQUEST_SET_PROTOCOL   usbHIDRequestType = 11
)

var interfaceRequestDescriptions = map[usbHIDRequestType]string{
	usb_HID_REQUEST_GET_REPORT:     "usb_HID_REQUEST_GET_REPORT",
	usb_HID_REQUEST_GET_IDLE:       "usb_HID_REQUEST_GET_IDLE",
	usb_HID_REQUEST_GET_PROTOCOL:   "usb_HID_REQUEST_GET_PROTOCOL",
	usb_HID_REQUEST_GET_DESCRIPTOR: "usb_HID_REQUEST_GET_DESCRIPTOR",
	usb_HID_REQUEST_SET_DESCRIPTOR: "usb_HID_REQUEST_SET_DESCRIPTOR",
	usb_HID_REQUEST_SET_REPORT:     "usb_HID_REQUEST_SET_REPORT",
	usb_HID_REQUEST_SET_IDLE:       "usb_HID_REQUEST_SET_IDLE",
	usb_HID_REQUEST_SET_PROTOCOL:   "usb_HID_REQUEST_SET_PROTOCOL",
}

type usbDirection uint8

const (
	usb_HOST_TO_DEVICE usbDirection = 0
	usb_DEVICE_TO_HOST usbDirection = 1
)

var requestDirectionDescriptions = map[usbDirection]string{
	usb_HOST_TO_DEVICE: "usb_HOST_TO_DEVICE",
	usb_DEVICE_TO_HOST: "usb_DEVICE_TO_HOST",
}

type usbRequestClass uint8

const (
	usb_REQUEST_CLASS_STANDARD usbRequestClass = 0
	usb_REQUEST_CLASS_CLASS    usbRequestClass = 1
	usb_REQUEST_CLASS_VENDOR   usbRequestClass = 2
	usb_REQUEST_CLASS_RESERVED usbRequestClass = 3
)

var requestClassDescriptons = map[usbRequestClass]string{
	usb_REQUEST_CLASS_STANDARD: "usb_REQUEST_CLASS_STANDARD",
	usb_REQUEST_CLASS_CLASS:    "usb_REQUEST_CLASS_CLASS",
	usb_REQUEST_CLASS_VENDOR:   "usb_REQUEST_CLASS_VENDOR",
	usb_REQUEST_CLASS_RESERVED: "usb_REQUEST_CLASS_RESERVED",
}

type usbRequestRecipient uint8

const (
	usb_REQUEST_RECIPIENT_DEVICE    usbRequestRecipient = 0
	usb_REQUEST_RECIPIENT_INTERFACE usbRequestRecipient = 1
	usb_REQUEST_RECIPIENT_ENDPOINT  usbRequestRecipient = 2
	usb_REQUEST_RECIPIENT_OTHER     usbRequestRecipient = 3
)

var requestRecipientDescriptions = map[usbRequestRecipient]string{
	usb_REQUEST_RECIPIENT_DEVICE:    "usb_REQUEST_RECIPIENT_DEVICE",
	usb_REQUEST_RECIPIENT_INTERFACE: "usb_REQUEST_RECIPIENT_INTERFACE",
	usb_REQUEST_RECIPIENT_ENDPOINT:  "usb_REQUEST_RECIPIENT_ENDPOINT",
	usb_REQUEST_RECIPIENT_OTHER:     "usb_REQUEST_RECIPIENT_OTHER",
}

const (
	usb_CONFIG_ATTR_BASE          = 0b10000000
	usb_CONFIG_ATTR_SELF_POWERED  = 0b01000000
	usb_CONFIG_ATTR_REMOTE_WAKEUP = 0b00100000

	usb_INTERFACE_CLASS_HID = 3

	usb_LANGID_ENG_USA = 0x0409
)

type usbSetupPacket struct {
	BmRequestType uint8
	BRequest      usbRequestType
	WValue        uint16
	WIndex        uint16
	WLength       uint16
}

func (setup usbSetupPacket) String() string {
	var requestDescription string
	var ok bool
	if setup.recipient() == usb_REQUEST_RECIPIENT_DEVICE {
		requestDescription, ok = deviceRequestDescriptons[setup.BRequest]
	} else {
		requestDescription, ok = interfaceRequestDescriptions[usbHIDRequestType(setup.BRequest)]
	}
	if !ok {
		requestDescription = fmt.Sprintf("0x%x", setup.BRequest)
	}
	return fmt.Sprintf("usbSetupPacket{ Direction: %s, RequestType: %s, Recipient: %s, BRequest: %s, WValue: 0x%x, WIndex: %d, WLength: %d }",
		requestDirectionDescriptions[setup.direction()],
		requestClassDescriptons[setup.requestClass()],
		requestRecipientDescriptions[setup.recipient()],
		requestDescription,
		setup.WValue,
		setup.WIndex,
		setup.WLength)
}

func (setup *usbSetupPacket) direction() usbDirection {
	return usbDirection((setup.BmRequestType >> 7) & 1)
}

func (setup *usbSetupPacket) requestClass() usbRequestClass {
	return usbRequestClass((setup.BmRequestType >> 4) & 0b11)
}

func (setup *usbSetupPacket) recipient() usbRequestRecipient {
	return usbRequestRecipient(setup.BmRequestType & 0b1111)
}

type usbDeviceDescriptor struct {
	BLength            uint8
	BDescriptorType    usbDescriptorType
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

type usbConfigurationDescriptor struct {
	BLength             uint8
	BDescriptorType     usbDescriptorType
	WTotalLength        uint16
	BNumInterfaces      uint8
	BConfigurationValue uint8
	IConfiguration      uint8
	BmAttributes        uint8
	BMaxPower           uint8
}

type usbInterfaceDescriptor struct {
	BLength            uint8
	BDescriptorType    usbDescriptorType
	BInterfaceNumber   uint8
	BAlternateSetting  uint8
	BNumEndpoints      uint8
	BInterfaceClass    uint8
	BInterfaceSubclass uint8
	BInterfaceProtocol uint8
	IInterface         uint8
}

type usbHIDDescriptor struct {
	BLength                 uint8
	BDescriptorType         usbDescriptorType
	BcdHID                  uint16
	BCountryCode            uint8
	BNumDescriptors         uint8
	BClassDescriptorType    usbDescriptorType
	WReportDescriptorLength uint16
}

type usbEndpointDescriptor struct {
	BLength          uint8
	BDescriptorType  usbDescriptorType
	BEndpointAddress uint8
	BmAttributes     uint8
	WMaxPacketSize   uint16
	BInterval        uint8
}

type usbStringDescriptorHeader struct {
	BLength         uint8
	BDescriptorType usbDescriptorType
}

type usbISOPacketDescriptor struct {
	Offset       uint32
	Length       uint32
	ActualLength uint32
	Status       uint32
}

func getDescriptorTypeAndIndex(wValue uint16) (usbDescriptorType, uint8) {
	descriptorType := usbDescriptorType(wValue >> 8)
	descriptorIndex := uint8(wValue & 0xFF)
	return descriptorType, descriptorIndex
}
