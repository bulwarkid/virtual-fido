package usbip

import "fmt"

type USBRequestType uint8

const (
	USB_REQUEST_GET_STATUS        USBRequestType = 0
	USB_REQUEST_CLEAR_FEATURE     USBRequestType = 1
	USB_REQUEST_SET_FEATURE       USBRequestType = 3
	USB_REQUEST_SET_ADDRESS       USBRequestType = 5
	USB_REQUEST_GET_DESCRIPTOR    USBRequestType = 6
	USB_REQUEST_SET_DESCRIPTOR    USBRequestType = 7
	USB_REQUEST_GET_CONFIGURATION USBRequestType = 8
	USB_REQUEST_SET_CONFIGURATION USBRequestType = 9
	USB_REQUEST_GET_INTERFACE     USBRequestType = 10
	USB_REQUEST_SET_INTERFACE     USBRequestType = 11
	USB_REQUEST_SYNCH_FRAME       USBRequestType = 12
)

var deviceRequestDescriptons = map[USBRequestType]string{
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

type USBDescriptorType uint8

const (
	USB_DESCRIPTOR_DEVICE                    USBDescriptorType = 1
	USB_DESCRIPTOR_CONFIGURATION             USBDescriptorType = 2
	USB_DESCRIPTOR_STRING                    USBDescriptorType = 3
	USB_DESCRIPTOR_INTERFACE                 USBDescriptorType = 4
	USB_DESCRIPTOR_ENDPOINT                  USBDescriptorType = 5
	USB_DESCRIPTOR_DEVICE_QUALIFIER          USBDescriptorType = 6
	USB_DESCRIPTOR_OTHER_SPEED_CONFIGURATION USBDescriptorType = 7
	USB_DESCRIPTOR_INTERFACE_POWER           USBDescriptorType = 8
	USB_DESCRIPTOR_HID                       USBDescriptorType = 33
	USB_DESCRIPTOR_HID_REPORT                USBDescriptorType = 34
)

var descriptorTypeDescriptions = map[USBDescriptorType]string{
	USB_DESCRIPTOR_DEVICE:                    "USB_DESCRIPTOR_DEVICE",
	USB_DESCRIPTOR_CONFIGURATION:             "USB_DESCRIPTOR_CONFIGURATION",
	USB_DESCRIPTOR_STRING:                    "USB_DESCRIPTOR_STRING",
	USB_DESCRIPTOR_INTERFACE:                 "USB_DESCRIPTOR_INTERFACE",
	USB_DESCRIPTOR_ENDPOINT:                  "USB_DESCRIPTOR_ENDPOINT",
	USB_DESCRIPTOR_DEVICE_QUALIFIER:          "USB_DESCRIPTOR_DEVICE_QUALIFIER",
	USB_DESCRIPTOR_OTHER_SPEED_CONFIGURATION: "USB_DESCRIPTOR_OTHER_SPEED_CONFIGURATION",
	USB_DESCRIPTOR_INTERFACE_POWER:           "USB_DESCRIPTOR_INTERFACE_POWER",
	USB_DESCRIPTOR_HID:                       "USB_DESCRIPTOR_HID",
	USB_DESCRIPTOR_HID_REPORT:                "USB_DESCRIPTOR_HID_REPORT",
}

type USBHIDRequestType uint8

const (
	USB_HID_REQUEST_GET_REPORT     USBHIDRequestType = 1
	USB_HID_REQUEST_GET_IDLE       USBHIDRequestType = 2
	USB_HID_REQUEST_GET_PROTOCOL   USBHIDRequestType = 3
	USB_HID_REQUEST_GET_DESCRIPTOR USBHIDRequestType = 6
	USB_HID_REQUEST_SET_DESCRIPTOR USBHIDRequestType = 7
	USB_HID_REQUEST_SET_REPORT     USBHIDRequestType = 9
	USB_HID_REQUEST_SET_IDLE       USBHIDRequestType = 10
	USB_HID_REQUEST_SET_PROTOCOL   USBHIDRequestType = 11
)

var interfaceRequestDescriptions = map[USBHIDRequestType]string{
	USB_HID_REQUEST_GET_REPORT:     "USB_HID_REQUEST_GET_REPORT",
	USB_HID_REQUEST_GET_IDLE:       "USB_HID_REQUEST_GET_IDLE",
	USB_HID_REQUEST_GET_PROTOCOL:   "USB_HID_REQUEST_GET_PROTOCOL",
	USB_HID_REQUEST_GET_DESCRIPTOR: "USB_HID_REQUEST_GET_DESCRIPTOR",
	USB_HID_REQUEST_SET_DESCRIPTOR: "USB_HID_REQUEST_SET_DESCRIPTOR",
	USB_HID_REQUEST_SET_REPORT:     "USB_HID_REQUEST_SET_REPORT",
	USB_HID_REQUEST_SET_IDLE:       "USB_HID_REQUEST_SET_IDLE",
	USB_HID_REQUEST_SET_PROTOCOL:   "USB_HID_REQUEST_SET_PROTOCOL",
}

type USBDirection uint8

const (
	USB_HOST_TO_DEVICE USBDirection = 0
	USB_DEVICE_TO_HOST USBDirection = 1
)

var requestDirectionDescriptions = map[USBDirection]string{
	USB_HOST_TO_DEVICE: "USB_HOST_TO_DEVICE",
	USB_DEVICE_TO_HOST: "USB_DEVICE_TO_HOST",
}

type USBRequestClass uint8

const (
	USB_REQUEST_CLASS_STANDARD USBRequestClass = 0
	USB_REQUEST_CLASS_CLASS    USBRequestClass = 1
	USB_REQUEST_CLASS_VENDOR   USBRequestClass = 2
	USB_REQUEST_CLASS_RESERVED USBRequestClass = 3
)

var requestClassDescriptons = map[USBRequestClass]string{
	USB_REQUEST_CLASS_STANDARD: "USB_REQUEST_CLASS_STANDARD",
	USB_REQUEST_CLASS_CLASS:    "USB_REQUEST_CLASS_CLASS",
	USB_REQUEST_CLASS_VENDOR:   "USB_REQUEST_CLASS_VENDOR",
	USB_REQUEST_CLASS_RESERVED: "USB_REQUEST_CLASS_RESERVED",
}

type USBRequestRecipient uint8

const (
	USB_REQUEST_RECIPIENT_DEVICE    USBRequestRecipient = 0
	USB_REQUEST_RECIPIENT_INTERFACE USBRequestRecipient = 1
	USB_REQUEST_RECIPIENT_ENDPOINT  USBRequestRecipient = 2
	USB_REQUEST_RECIPIENT_OTHER     USBRequestRecipient = 3
)

var requestRecipientDescriptions = map[USBRequestRecipient]string{
	USB_REQUEST_RECIPIENT_DEVICE:    "USB_REQUEST_RECIPIENT_DEVICE",
	USB_REQUEST_RECIPIENT_INTERFACE: "USB_REQUEST_RECIPIENT_INTERFACE",
	USB_REQUEST_RECIPIENT_ENDPOINT:  "USB_REQUEST_RECIPIENT_ENDPOINT",
	USB_REQUEST_RECIPIENT_OTHER:     "USB_REQUEST_RECIPIENT_OTHER",
}

const (
	USB_CONFIG_ATTR_BASE          = 0b10000000
	USB_CONFIG_ATTR_SELF_POWERED  = 0b01000000
	USB_CONFIG_ATTR_REMOTE_WAKEUP = 0b00100000

	USB_INTERFACE_CLASS_HID = 3

	USB_LANGID_ENG_USA = 0x0409
)

type USBSetupPacket struct {
	BmRequestType uint8
	BRequest      USBRequestType
	WValue        uint16
	WIndex        uint16
	WLength       uint16
}

func (setup USBSetupPacket) String() string {
	var requestDescription string
	var ok bool
	if setup.recipient() == USB_REQUEST_RECIPIENT_DEVICE {
		requestDescription, ok = deviceRequestDescriptons[setup.BRequest]
	} else {
		requestDescription, ok = interfaceRequestDescriptions[USBHIDRequestType(setup.BRequest)]
	}
	if !ok {
		requestDescription = fmt.Sprintf("0x%x", setup.BRequest)
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

func getDescriptorTypeAndIndex(wValue uint16) (USBDescriptorType, uint8) {
	descriptorType := USBDescriptorType(wValue >> 8)
	descriptorIndex := uint8(wValue & 0xFF)
	return descriptorType, descriptorIndex
}
