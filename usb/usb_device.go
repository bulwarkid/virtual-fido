package usb

import (
	"bytes"
	"fmt"
	"sync"
	"unsafe"

	"github.com/bulwarkid/virtual-fido/usbip"
	"github.com/bulwarkid/virtual-fido/util"
)

var usbLogger = util.NewLogger("[USB] ", util.LogLevelTrace)

type USBDeviceDelegate interface {
	RemoveWaitingRequest(id uint32) bool
	HandleMessage(transferBuffer []byte)
	GetResponse(id uint32, timeout int64) []byte
}

type USBDevice struct {
	delegate   USBDeviceDelegate
	outputLock sync.Locker
}

func NewUSBDevice(delegate USBDeviceDelegate) *USBDevice {
	return &USBDevice{
		delegate:   delegate,
		outputLock: &sync.Mutex{},
	}
}

func (device *USBDevice) BusID() string {
	return "2-2"
}

func (device *USBDevice) DeviceSummary() usbip.USBIPDeviceSummary {
	summary := usbip.USBIPDeviceSummary{
		Header: usbip.USBIPDeviceSummaryHeader{
			Busnum:              2,
			Devnum:              2,
			Speed:               2,
			IdVendor:            0,
			IdProduct:           0,
			BcdDevice:           0,
			BDeviceClass:        0,
			BDeviceSubclass:     0,
			BDeviceProtocol:     0,
			BConfigurationValue: 0,
			BNumConfigurations:  1,
			BNumInterfaces:      1,
		},
		DeviceInterface: usbip.USBIPDeviceInterface{
			BInterfaceClass:    3,
			BInterfaceSubclass: 0,
			Padding:            0,
		},
	}
	copy(summary.Header.Path[:], []byte("/device/0"))
	copy(summary.Header.BusID[:], []byte("2-2"))
	return summary
}

func (device *USBDevice) RemoveWaitingRequest(id uint32) bool {
	return device.delegate.RemoveWaitingRequest(id)
}

func (device *USBDevice) HandleMessage(id uint32, onFinish func(), endpoint uint32, setupBytes [8]byte, transferBuffer []byte) {
	setup := util.ReadBE[usbSetupPacket](bytes.NewBuffer(setupBytes[:]))
	usbLogger.Printf("USB MESSAGE - ENDPOINT %d\n\n", endpoint)
	if endpoint == 0 {
		device.handleControlMessage(setup, transferBuffer)
		onFinish()
	} else if endpoint == 1 {
		go device.handleOutputMessage(id, transferBuffer, onFinish)
		// handleOutputMessage should handle calling onFinish
	} else if endpoint == 2 {
		usbLogger.Printf("INPUT TRANSFER BUFFER: %#v\n\n", transferBuffer)
		go device.delegate.HandleMessage(transferBuffer)
		onFinish()
	} else {
		util.Panic(fmt.Sprintf("Invalid USB endpoint: %d", endpoint))
	}
}

func (device *USBDevice) handleControlMessage(setup usbSetupPacket, transferBuffer []byte) {
	usbLogger.Printf("CONTROL MESSAGE: %s\n\n", setup)
	if setup.direction() == usbHostToDevice {
		usbLogger.Printf("TRANSFER BUFFER: %v\n\n", transferBuffer)
	}
	if setup.recipient() == usbRequestRecipientDevice {
		device.handleDeviceRequest(setup, transferBuffer)
	} else if setup.recipient() == usbRequestRecipientInterface {
		device.handleInterfaceRequest(setup, transferBuffer)
	} else {
		util.Panic(fmt.Sprintf("Invalid CMD_SUBMIT recipient: %d", setup.recipient()))
	}
}

func (device *USBDevice) handleOutputMessage(id uint32, transferBuffer []byte, onFinish func()) {
	// Only process one output message at a time in order to maintain message order
	device.outputLock.Lock()
	response := device.delegate.GetResponse(id, 1000)
	if response != nil {
		copy(transferBuffer, response)
		onFinish()
	}
	device.outputLock.Unlock()
}

func (device *USBDevice) handleDeviceRequest(setup usbSetupPacket, transferBuffer []byte) {
	switch setup.bRequest {
	case usbRequestGetDescriptor:
		descriptorType, descriptorIndex := getDescriptorTypeAndIndex(setup.wValue)
		descriptor := device.getDescriptor(descriptorType, descriptorIndex)
		copy(transferBuffer, descriptor)
	case usbRequestSetConfiguration:
		usbLogger.Printf("SET_CONFIGURATION: No-op\n\n")
		// TODO: Handle configuration changes
		// No-op since we can't change configuration
		return
	case usbRequestGetStatus:
		copy(transferBuffer, []byte{1})
	default:
		util.Panic(fmt.Sprintf("Invalid CMD_SUBMIT bRequest: %d", setup.bRequest))
	}
}

func (device *USBDevice) handleInterfaceRequest(setup usbSetupPacket, transferBuffer []byte) {
	switch usbHIDRequestType(setup.bRequest) {
	case usbHIDRequestSetIdle:
		// No-op since we are made in software
		usbLogger.Printf("SET IDLE: No-op\n\n")
	case usbHIDRequestSetProtocol:
		// No-op since we are always in report protocol, no boot protocol
	case usbHIDRequestGetDescriptor:
		descriptorType, descriptorIndex := getDescriptorTypeAndIndex(setup.wValue)
		usbLogger.Printf("GET INTERFACE DESCRIPTOR: Type: %s Index: %d\n\n", descriptorTypeDescriptions[descriptorType], descriptorIndex)
		switch descriptorType {
		case usbDescriptorHIDReport:
			usbLogger.Printf("HID REPORT: %v\n\n", device.getHIDReport())
			copy(transferBuffer, device.getHIDReport())
		default:
			util.Panic(fmt.Sprintf("Invalid USB Interface descriptor: %d - %d", descriptorType, descriptorIndex))
		}
	default:
		util.Panic(fmt.Sprintf("Invalid USB Interface bRequest: %d", setup.bRequest))
	}
}

func (device *USBDevice) getDescriptor(descriptorType usbDescriptorType, index uint8) []byte {
	usbLogger.Printf("GET DESCRIPTOR: Type: %s Index: %d\n\n", descriptorTypeDescriptions[descriptorType], index)
	switch descriptorType {
	case usbDescriptorDevice:
		descriptor := device.getDeviceDescriptor()
		usbLogger.Printf("DEVICE DESCRIPTOR: %#v\n\n", descriptor)
		return util.ToLE(descriptor)
	case usbDescriptorConfiguration:
		buffer := new(bytes.Buffer)
		interfaceDescriptor := device.getInterfaceDescriptor()
		buffer.Write(util.ToLE(interfaceDescriptor))
		hid := device.getHIDDescriptor(device.getHIDReport())
		buffer.Write(util.ToLE(hid))
		endpoints := device.getEndpointDescriptors()
		for _, endpoint := range endpoints {
			usbLogger.Printf("ENDPOINT: %#v\n\n", endpoint)
			buffer.Write(util.ToLE(endpoint))
		}
		configBytes := buffer.Bytes()
		config := device.getConfigurationDescriptor(uint16(len(configBytes)))
		usbLogger.Printf("CONFIGURATION: %#v\n\nINTERFACE: %#v\n\nHID: %#v\n\n", config, interfaceDescriptor, hid)
		return append(util.ToLE(config), configBytes...)
	case usbDescriptorString:
		message := device.getStringDescriptor(index)
		header := usbStringDescriptorHeader{
			bLength:         0,
			bDescriptorType: usbDescriptorString,
		}
		header.bLength = uint8(unsafe.Sizeof(header)) + uint8(len(message))
		usbLogger.Printf("STRING: Length: %d Message: \"%s\" Bytes: %v\n\n", header.bLength, message, message)
		return util.Concat(util.ToLE(header), message)
	default:
		util.Panic(fmt.Sprintf("Invalid Descriptor type: %d", descriptorType))
	}
	return nil
}

func (device *USBDevice) getDeviceDescriptor() usbDeviceDescriptor {
	return usbDeviceDescriptor{
		bLength:            util.SizeOf[usbDeviceDescriptor](),
		bDescriptorType:    usbDescriptorDevice,
		bcdUSB:             0x0110,
		bDeviceClass:       0,
		bDeviceSubclass:    0,
		bDeviceProtocol:    0,
		bMaxPacketSize:     64,
		idVendor:           0,
		idProduct:          0,
		bcdDevice:          0x1,
		iManufacturer:      1,
		iProduct:           2,
		iSerialNumber:      3,
		bNumConfigurations: 1,
	}
}

func (device *USBDevice) getConfigurationDescriptor(configLength uint16) usbConfigurationDescriptor {
	totalLength := uint16(util.SizeOf[usbConfigurationDescriptor]()) + configLength
	return usbConfigurationDescriptor{
		bLength:             util.SizeOf[usbConfigurationDescriptor](),
		bDescriptorType:     usbDescriptorConfiguration,
		wTotalLength:        totalLength,
		bNumInterfaces:      1,
		bConfigurationValue: 0,
		iConfiguration:      4,
		bmAttributes:        usbConfigAttributeBase | usbConfigAttributeSelfPowered,
		bMaxPower:           0,
	}
}

func (device *USBDevice) getInterfaceDescriptor() usbInterfaceDescriptor {
	return usbInterfaceDescriptor{
		bLength:            util.SizeOf[usbInterfaceDescriptor](),
		bDescriptorType:    usbDescriptorInterface,
		bInterfaceNumber:   0,
		bAlternateSetting:  0,
		bNumEndpoints:      2,
		bInterfaceClass:    usbInterfaceClassHID,
		bInterfaceSubclass: 0,
		bInterfaceProtocol: 0,
		iInterface:         5,
	}
}

func (device *USBDevice) getHIDDescriptor(hidReportDescriptor []byte) usbHIDDescriptor {
	return usbHIDDescriptor{
		bLength:                 util.SizeOf[usbHIDDescriptor](),
		bDescriptorType:         usbDescriptorHID,
		bcdHID:                  0x0101,
		bCountryCode:            0,
		bNumDescriptors:         1,
		bClassDescriptorType:    usbDescriptorHIDReport,
		wReportDescriptorLength: uint16(len(hidReportDescriptor)),
	}
}

func (device *USBDevice) getHIDReport() []byte {
	// Manually calculated using the HID Report calculator for a FIDO device
	return []byte{6, 208, 241, 9, 1, 161, 1, 9, 32, 20, 37, 255, 117, 8, 149, 64, 129, 2, 9, 33, 20, 37, 255, 117, 8, 149, 64, 145, 2, 192}
}

func (device *USBDevice) getEndpointDescriptors() []usbEndpointDescriptor {
	length := util.SizeOf[usbEndpointDescriptor]()
	return []usbEndpointDescriptor{
		{
			bLength:          length,
			bDescriptorType:  usbDescriptorEndpoint,
			bEndpointAddress: 0b10000001,
			bmAttributes:     0b00000011,
			wMaxPacketSize:   64,
			bInterval:        255,
		},
		{
			bLength:          length,
			bDescriptorType:  usbDescriptorEndpoint,
			bEndpointAddress: 0b00000010,
			bmAttributes:     0b00000011,
			wMaxPacketSize:   64,
			bInterval:        255,
		},
	}
}

func (device *USBDevice) getStringDescriptor(index uint8) []byte {
	switch index {
	case 0:
		return util.ToLE[uint16](usbLangIDEngUSA)
	case 1:
		return util.Utf16encode("No Company")
	case 2:
		return util.Utf16encode("Virtual FIDO")
	case 3:
		return util.Utf16encode("No Serial Number")
	case 4:
		return util.Utf16encode("String 4")
	case 5:
		return util.Utf16encode("Default Interface")
	default:
		util.Panic(fmt.Sprintf("Invalid string descriptor index: %d", index))
	}
	return nil
}
