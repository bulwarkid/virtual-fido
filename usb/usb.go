package usb

import "fmt"

type usbRequestType uint8

const (
	usbRequestGetStatus        usbRequestType = 0
	usbRequestClearFeature     usbRequestType = 1
	usbRequestSetFeature       usbRequestType = 3
	usbRequestSetAddress       usbRequestType = 5
	usbRequestGetDescriptor    usbRequestType = 6
	usbRequestSetDescriptor    usbRequestType = 7
	usbRequestGetConfiguration usbRequestType = 8
	usbRequestSetConfiguration usbRequestType = 9
	usbRequestGetInterface     usbRequestType = 10
	usbRequestSetInterface     usbRequestType = 11
	usbRequestSynchFrame       usbRequestType = 12
)

var deviceRequestDescriptons = map[usbRequestType]string{
	usbRequestGetStatus:        "usbRequestGetStatus",
	usbRequestClearFeature:     "usbRequestClearFeature",
	usbRequestSetFeature:       "usbRequestSetFeature",
	usbRequestSetAddress:       "usbRequestSetAddress",
	usbRequestGetDescriptor:    "usbRequestGetDescriptor",
	usbRequestSetDescriptor:    "usbRequestSetDescriptor",
	usbRequestGetConfiguration: "usbRequestGetConfiguration",
	usbRequestSetConfiguration: "usbRequestSetConfiguration",
	usbRequestGetInterface:     "usbRequestGetInterface",
	usbRequestSetInterface:     "usbRequestSetInterface",
	usbRequestSynchFrame:       "usbRequestSynchFrame",
}

type usbDescriptorType uint8

const (
	usbDescriptorDevice                  usbDescriptorType = 1
	usbDescriptorConfiguration           usbDescriptorType = 2
	usbDescriptorString                  usbDescriptorType = 3
	usbDescriptorInterface               usbDescriptorType = 4
	usbDescriptorEndpoint                usbDescriptorType = 5
	usbDescriptorDeviceQualifier         usbDescriptorType = 6
	usbDescriptorOtherSpeedConfiguration usbDescriptorType = 7
	usbDescriptorInterfacePower          usbDescriptorType = 8
	usbDescriptorHID                     usbDescriptorType = 33
	usbDescriptorHIDReport               usbDescriptorType = 34
)

var descriptorTypeDescriptions = map[usbDescriptorType]string{
	usbDescriptorDevice:                  "usbDescriptorDevice",
	usbDescriptorConfiguration:           "usbDescriptorConfiguration",
	usbDescriptorString:                  "usbDescriptorString",
	usbDescriptorInterface:               "usbDescriptorInterface",
	usbDescriptorEndpoint:                "usbDescriptorEndpoint",
	usbDescriptorDeviceQualifier:         "usbDescriptorDeviceQualifier",
	usbDescriptorOtherSpeedConfiguration: "usbDescriptorOtherSpeedConfiguration",
	usbDescriptorInterfacePower:          "usbDescriptorInterfacePower",
	usbDescriptorHID:                     "usbDescriptorHID",
	usbDescriptorHIDReport:               "usbDescriptorHIDReport",
}

type usbHIDRequestType uint8

const (
	usbHIDRequestGetReport     usbHIDRequestType = 1
	usbHIDRequestGetIdle       usbHIDRequestType = 2
	usbHIDRequestGetProtocol   usbHIDRequestType = 3
	usbHIDRequestGetDescriptor usbHIDRequestType = 6
	usbHIDRequestSetDescriptor usbHIDRequestType = 7
	usbHIDRequestSetReport     usbHIDRequestType = 9
	usbHIDRequestSetIdle       usbHIDRequestType = 10
	usbHIDRequestSetProtocol   usbHIDRequestType = 11
)

var interfaceRequestDescriptions = map[usbHIDRequestType]string{
	usbHIDRequestGetReport:     "usbHIDRequestGetReport",
	usbHIDRequestGetIdle:       "usbHIDRequestGetIdle",
	usbHIDRequestGetProtocol:   "usbHIDRequestGetProtocol",
	usbHIDRequestGetDescriptor: "usbHIDRequestGetDescriptor",
	usbHIDRequestSetDescriptor: "usbHIDRequestSetDescriptor",
	usbHIDRequestSetReport:     "usbHIDRequestSetReport",
	usbHIDRequestSetIdle:       "usbHIDRequestSetIdle",
	usbHIDRequestSetProtocol:   "usbHIDRequestSetProtocol",
}

type usbDirection uint8

const (
	usbHostToDevice usbDirection = 0
	usbDeviceToHost usbDirection = 1
)

var requestDirectionDescriptions = map[usbDirection]string{
	usbHostToDevice: "usbHostToDevice",
	usbDeviceToHost: "usbDeviceToHost",
}

type usbRequestClass uint8

const (
	usbRequestClassStandard usbRequestClass = 0
	usbRequestClassClass    usbRequestClass = 1
	usbRequestClassVendor   usbRequestClass = 2
	usbRequestClassReserved usbRequestClass = 3
)

var requestClassDescriptons = map[usbRequestClass]string{
	usbRequestClassStandard: "usbRequestClassStandard",
	usbRequestClassClass:    "usbRequestClassClass",
	usbRequestClassVendor:   "usbRequestClassVendor",
	usbRequestClassReserved: "usbRequestClassReserved",
}

type usbRequestRecipient uint8

const (
	usbRequestRecipientDevice    usbRequestRecipient = 0
	usbRequestRecipientInterface usbRequestRecipient = 1
	usbRequestRecipientEndpoint  usbRequestRecipient = 2
	usbRequestRecipientOther     usbRequestRecipient = 3
)

var requestRecipientDescriptions = map[usbRequestRecipient]string{
	usbRequestRecipientDevice:    "usbRequestRecipientDevice",
	usbRequestRecipientInterface: "usbRequestRecipientInterface",
	usbRequestRecipientEndpoint:  "usbRequestRecipientEndpoint",
	usbRequestRecipientOther:     "usbRequestRecipientOther",
}

const (
	usbConfigAttributeBase         = 0b10000000
	usbConfigAttributeSelfPowered  = 0b01000000
	usbConfigAttributeRemoteWakeup = 0b00100000

	usbInterfaceClassHID = 3

	usbLangIDEngUSA = 0x0409
)

type usbSetupPacket struct {
	bmRequestType uint8
	bRequest      usbRequestType
	wValue        uint16
	wIndex        uint16
	wLength       uint16
}

func (setup usbSetupPacket) String() string {
	var requestDescription string
	var ok bool
	if setup.recipient() == usbRequestRecipientDevice {
		requestDescription, ok = deviceRequestDescriptons[setup.bRequest]
	} else {
		requestDescription, ok = interfaceRequestDescriptions[usbHIDRequestType(setup.bRequest)]
	}
	if !ok {
		requestDescription = fmt.Sprintf("0x%x", setup.bRequest)
	}
	return fmt.Sprintf("USBSetupPacket{ Direction: %s, RequestType: %s, Recipient: %s, BRequest: %s, WValue: 0x%x, WIndex: %d, WLength: %d }",
		requestDirectionDescriptions[setup.direction()],
		requestClassDescriptons[setup.requestClass()],
		requestRecipientDescriptions[setup.recipient()],
		requestDescription,
		setup.wValue,
		setup.wIndex,
		setup.wLength)
}

func (setup *usbSetupPacket) direction() usbDirection {
	return usbDirection((setup.bmRequestType >> 7) & 1)
}

func (setup *usbSetupPacket) requestClass() usbRequestClass {
	return usbRequestClass((setup.bmRequestType >> 4) & 0b11)
}

func (setup *usbSetupPacket) recipient() usbRequestRecipient {
	return usbRequestRecipient(setup.bmRequestType & 0b1111)
}

type usbDeviceDescriptor struct {
	bLength            uint8
	bDescriptorType    usbDescriptorType
	bcdUSB             uint16
	bDeviceClass       uint8
	bDeviceSubclass    uint8
	bDeviceProtocol    uint8
	bMaxPacketSize     uint8
	idVendor           uint16
	idProduct          uint16
	bcdDevice          uint16
	iManufacturer      uint8
	iProduct           uint8
	iSerialNumber      uint8
	bNumConfigurations uint8
}

type usbConfigurationDescriptor struct {
	bLength             uint8
	bDescriptorType     usbDescriptorType
	wTotalLength        uint16
	bNumInterfaces      uint8
	bConfigurationValue uint8
	iConfiguration      uint8
	bmAttributes        uint8
	bMaxPower           uint8
}

type usbInterfaceDescriptor struct {
	bLength            uint8
	bDescriptorType    usbDescriptorType
	bInterfaceNumber   uint8
	bAlternateSetting  uint8
	bNumEndpoints      uint8
	bInterfaceClass    uint8
	bInterfaceSubclass uint8
	bInterfaceProtocol uint8
	iInterface         uint8
}

type usbHIDDescriptor struct {
	bLength                 uint8
	bDescriptorType         usbDescriptorType
	bcdHID                  uint16
	bCountryCode            uint8
	bNumDescriptors         uint8
	bClassDescriptorType    usbDescriptorType
	wReportDescriptorLength uint16
}

type usbEndpointDescriptor struct {
	bLength          uint8
	bDescriptorType  usbDescriptorType
	bEndpointAddress uint8
	bmAttributes     uint8
	wMaxPacketSize   uint16
	bInterval        uint8
}

type usbStringDescriptorHeader struct {
	bLength         uint8
	bDescriptorType usbDescriptorType
}

func getDescriptorTypeAndIndex(wValue uint16) (usbDescriptorType, uint8) {
	descriptorType := usbDescriptorType(wValue >> 8)
	descriptorIndex := uint8(wValue & 0xFF)
	return descriptorType, descriptorIndex
}
