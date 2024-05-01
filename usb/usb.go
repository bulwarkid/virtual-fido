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

func (descriptor usbDescriptorType) String() string {
	if s, ok := descriptorTypeDescriptions[descriptor]; ok {
		return s
	}
	return "Invalid"
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
	BmRequestType uint8
	BRequest      usbRequestType
	WValue        uint16
	WIndex        uint16
	WLength       uint16
}

func (setup usbSetupPacket) String() string {
	var requestDescription string
	var ok bool
	if setup.recipient() == usbRequestRecipientDevice {
		requestDescription, ok = deviceRequestDescriptons[setup.BRequest]
	} else {
		requestDescription, ok = interfaceRequestDescriptions[usbHIDRequestType(setup.BRequest)]
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

func (setup *usbSetupPacket) direction() usbDirection {
	return usbDirection((setup.BmRequestType >> 7) & 1)
}

func (setup *usbSetupPacket) setDirection(direction usbDirection) {
	setup.BmRequestType &= ^(uint8(1) << 7)
	setup.BmRequestType |= (uint8(direction) << 7)
}

func (setup *usbSetupPacket) requestClass() usbRequestClass {
	return usbRequestClass((setup.BmRequestType >> 4) & 0b11)
}

func (setup *usbSetupPacket) setRequestClass(class usbRequestClass) {
	setup.BmRequestType &= ^(uint8(0b11) << 4)
	setup.BmRequestType |= uint8(class) << 4
}

func (setup *usbSetupPacket) recipient() usbRequestRecipient {
	return usbRequestRecipient(setup.BmRequestType & 0b1111)
}

func (setup *usbSetupPacket) setRecipient(recipient usbRequestRecipient) {
	setup.BmRequestType &= ^uint8(0b1111)
	setup.BmRequestType |= uint8(recipient)
}

type usbEndpoint uint32

const (
	usbEndpointControl usbEndpoint = 0
	usbEndpointOutput  usbEndpoint = 1
	usbEndpointInput   usbEndpoint = 2
)

type usbDeviceDescriptor struct {
	BLength            uint8
	BDescriptorType    usbDescriptorType
	BcdUSB             uint16
	BDeviceClass       uint8
	BDeviceSubclass    uint8
	BDeviceProtocol    uint8
	BMaxPacketSize     uint8
	IDVendor           uint16
	IDProduct          uint16
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

const usbHIDCountryCodeNone uint8 = 0

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

func getDescriptorTypeAndIndex(wValue uint16) (usbDescriptorType, uint8) {
	descriptorType := usbDescriptorType(wValue >> 8)
	descriptorIndex := uint8(wValue & 0xFF)
	return descriptorType, descriptorIndex
}
