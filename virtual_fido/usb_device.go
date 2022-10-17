package virtual_fido

import (
	"bytes"
	"fmt"
	"sync"
	"unsafe"
)

type usbDevice interface {
	handleMessage(id uint32, onFinish func(), endpoint uint32, setup usbSetupPacket, transferBuffer []byte)
	removeWaitingRequest(id uint32) bool
	usbipSummary() usbipDeviceSummary
	usbipSummaryHeader() usbipDeviceSummaryHeader
}

var usbLogger = newLogger("[USB] ", false)

type usbDeviceImpl struct {
	Index         int
	ctapHIDServer *ctapHIDServer
	outputLock    sync.Locker
}

func newUSBDevice(ctapHIDServer *ctapHIDServer) *usbDeviceImpl {
	return &usbDeviceImpl{
		Index:         0,
		ctapHIDServer: ctapHIDServer,
		outputLock:    &sync.Mutex{},
	}
}

func (device *usbDeviceImpl) getDeviceDescriptor() usbDeviceDescriptor {
	return usbDeviceDescriptor{
		BLength:            sizeOf[usbDeviceDescriptor](),
		BDescriptorType:    usb_DESCRIPTOR_DEVICE,
		BcdUSB:             0x0110,
		BDeviceClass:       0,
		BDeviceSubclass:    0,
		BDeviceProtocol:    0,
		BMaxPacketSize:     64,
		IdVendor:           0,
		IdProduct:          0,
		BcdDevice:          0x1,
		IManufacturer:      1,
		IProduct:           2,
		ISerialNumber:      3,
		BNumConfigurations: 1,
	}
}

func (device *usbDeviceImpl) getConfigurationDescriptor() usbConfigurationDescriptor {
	totalLength := uint16(sizeOf[usbConfigurationDescriptor]()) +
		uint16(sizeOf[usbInterfaceDescriptor]()) +
		uint16(sizeOf[usbHIDDescriptor]()) +
		uint16(2*sizeOf[usbEndpointDescriptor]())
	return usbConfigurationDescriptor{
		BLength:             sizeOf[usbConfigurationDescriptor](),
		BDescriptorType:     usb_DESCRIPTOR_CONFIGURATION,
		WTotalLength:        totalLength,
		BNumInterfaces:      1,
		BConfigurationValue: 0,
		IConfiguration:      4,
		BmAttributes:        usb_CONFIG_ATTR_BASE | usb_CONFIG_ATTR_SELF_POWERED,
		BMaxPower:           0,
	}
}

func (device *usbDeviceImpl) getInterfaceDescriptor() usbInterfaceDescriptor {
	return usbInterfaceDescriptor{
		BLength:            sizeOf[usbInterfaceDescriptor](),
		BDescriptorType:    usb_DESCRIPTOR_INTERFACE,
		BInterfaceNumber:   0,
		BAlternateSetting:  0,
		BNumEndpoints:      2,
		BInterfaceClass:    usb_INTERFACE_CLASS_HID,
		BInterfaceSubclass: 0,
		BInterfaceProtocol: 0,
		IInterface:         5,
	}
}

func (device *usbDeviceImpl) getHIDDescriptor(hidReportDescriptor []byte) usbHIDDescriptor {
	return usbHIDDescriptor{
		BLength:                 sizeOf[usbHIDDescriptor](),
		BDescriptorType:         usb_DESCRIPTOR_HID,
		BcdHID:                  0x0101,
		BCountryCode:            0,
		BNumDescriptors:         1,
		BClassDescriptorType:    usb_DESCRIPTOR_HID_REPORT,
		WReportDescriptorLength: uint16(len(hidReportDescriptor)),
	}
}

func (device *usbDeviceImpl) getHIDReport() []byte {
	// Manually calculated using the HID Report calculator for a FIDO device
	return []byte{6, 208, 241, 9, 1, 161, 1, 9, 32, 20, 37, 255, 117, 8, 149, 64, 129, 2, 9, 33, 20, 37, 255, 117, 8, 149, 64, 145, 2, 192}
}

func (device *usbDeviceImpl) getEndpointDescriptors() []usbEndpointDescriptor {
	length := sizeOf[usbEndpointDescriptor]()
	return []usbEndpointDescriptor{
		{
			BLength:          length,
			BDescriptorType:  usb_DESCRIPTOR_ENDPOINT,
			BEndpointAddress: 0b10000001,
			BmAttributes:     0b00000011,
			WMaxPacketSize:   64,
			BInterval:        255,
		},
		{
			BLength:          length,
			BDescriptorType:  usb_DESCRIPTOR_ENDPOINT,
			BEndpointAddress: 0b00000010,
			BmAttributes:     0b00000011,
			WMaxPacketSize:   64,
			BInterval:        255,
		},
	}
}

func (device *usbDeviceImpl) getStringDescriptor(index uint8) []byte {
	switch index {
	case 1:
		return utf16encode("No Company")
	case 2:
		return utf16encode("Virtual FIDO")
	case 3:
		return utf16encode("No Serial Number")
	case 4:
		return utf16encode("String 4")
	case 5:
		return utf16encode("Default Interface")
	default:
		panic(fmt.Sprintf("Invalid string descriptor index: %d", index))
	}
}

func (device *usbDeviceImpl) getDescriptor(descriptorType usbDescriptorType, index uint8) []byte {
	usbLogger.Printf("GET DESCRIPTOR: Type: %s Index: %d\n\n", descriptorTypeDescriptions[descriptorType], index)
	switch descriptorType {
	case usb_DESCRIPTOR_DEVICE:
		descriptor := device.getDeviceDescriptor()
		usbLogger.Printf("DEVICE DESCRIPTOR: %#v\n\n", descriptor)
		return toLE(descriptor)
	case usb_DESCRIPTOR_CONFIGURATION:
		hidReport := device.getHIDReport()
		buffer := new(bytes.Buffer)
		config := device.getConfigurationDescriptor()
		interfaceDescriptor := device.getInterfaceDescriptor()
		hid := device.getHIDDescriptor(hidReport)
		usbLogger.Printf("CONFIGURATION: %#v\n\nINTERFACE: %#v\n\nHID: %#v\n\n", config, interfaceDescriptor, hid)
		buffer.Write(toLE(config))
		buffer.Write(toLE(interfaceDescriptor))
		buffer.Write(toLE(hid))
		endpoints := device.getEndpointDescriptors()
		for _, endpoint := range endpoints {
			usbLogger.Printf("ENDPOINT: %#v\n\n", endpoint)
			buffer.Write(toLE(endpoint))
		}
		return buffer.Bytes()
	case usb_DESCRIPTOR_STRING:
		var message []byte
		if index == 0 {
			message = toLE[uint16](usb_LANGID_ENG_USA)
		} else {
			message = device.getStringDescriptor(index)
		}
		var header usbStringDescriptorHeader
		length := uint8(unsafe.Sizeof(header)) + uint8(len(message))
		header = usbStringDescriptorHeader{
			BLength:         length,
			BDescriptorType: usb_DESCRIPTOR_STRING,
		}
		buffer := new(bytes.Buffer)
		buffer.Write(toLE(header))
		buffer.Write([]byte(message))
		usbLogger.Printf("STRING: Length: %d Message: \"%s\" Bytes: %v\n\n", header.BLength, message, buffer.Bytes())
		return buffer.Bytes()
	default:
		panic(fmt.Sprintf("Invalid Descriptor type: %d", descriptorType))
	}
}

func (device *usbDeviceImpl) usbipSummary() usbipDeviceSummary {
	return usbipDeviceSummary{
		Header:          device.usbipSummaryHeader(),
		DeviceInterface: device.usbipInterfacesSummary(),
	}
}

func (device *usbDeviceImpl) usbipSummaryHeader() usbipDeviceSummaryHeader {
	path := [256]byte{}
	copy(path[:], []byte("/device/"+fmt.Sprint(device.Index)))
	busId := [32]byte{}
	copy(busId[:], []byte("2-2"))
	return usbipDeviceSummaryHeader{
		Path:                path,
		BusId:               busId,
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
	}
}

func (device *usbDeviceImpl) usbipInterfacesSummary() usbipDeviceInterface {
	return usbipDeviceInterface{
		BInterfaceClass:    3,
		BInterfaceSubclass: 0,
		Padding:            0,
	}
}

func (device *usbDeviceImpl) handleDeviceRequest(
	setup usbSetupPacket,
	transferBuffer []byte) {
	switch setup.BRequest {
	case usb_REQUEST_GET_DESCRIPTOR:
		descriptorType, descriptorIndex := getDescriptorTypeAndIndex(setup.WValue)
		descriptor := device.getDescriptor(descriptorType, descriptorIndex)
		copy(transferBuffer, descriptor)
	case usb_REQUEST_SET_CONFIGURATION:
		usbLogger.Printf("SET_CONFIGURATION: No-op\n\n")
		// TODO: Handle configuration changes
		// No-op since we can't change configuration
		return
	case usb_REQUEST_GET_STATUS:
		copy(transferBuffer, []byte{1})
	default:
		panic(fmt.Sprintf("Invalid CMD_SUBMIT bRequest: %d", setup.BRequest))
	}
}

func (device *usbDeviceImpl) handleInterfaceRequest(setup usbSetupPacket, transferBuffer []byte) {
	switch usbHIDRequestType(setup.BRequest) {
	case usb_HID_REQUEST_SET_IDLE:
		// No-op since we are made in software
		usbLogger.Printf("SET IDLE: No-op\n\n")
	case usb_HID_REQUEST_SET_PROTOCOL:
		// No-op since we are always in report protocol, no boot protocol
	case usb_HID_REQUEST_GET_DESCRIPTOR:
		descriptorType, descriptorIndex := getDescriptorTypeAndIndex(setup.WValue)
		usbLogger.Printf("GET INTERFACE DESCRIPTOR: Type: %s Index: %d\n\n", descriptorTypeDescriptions[descriptorType], descriptorIndex)
		switch descriptorType {
		case usb_DESCRIPTOR_HID_REPORT:
			usbLogger.Printf("HID REPORT: %v\n\n", device.getHIDReport())
			copy(transferBuffer, device.getHIDReport())
		default:
			panic(fmt.Sprintf("Invalid USB Interface descriptor: %d - %d", descriptorType, descriptorIndex))
		}
	default:
		panic(fmt.Sprintf("Invalid USB Interface bRequest: %d", setup.BRequest))
	}
}

func (device *usbDeviceImpl) handleControlMessage(setup usbSetupPacket, transferBuffer []byte) {
	usbLogger.Printf("CONTROL MESSAGE: %s\n\n", setup)
	if setup.direction() == usb_HOST_TO_DEVICE {
		usbLogger.Printf("TRANSFER BUFFER: %v\n\n", transferBuffer)
	}
	if setup.recipient() == usb_REQUEST_RECIPIENT_DEVICE {
		device.handleDeviceRequest(setup, transferBuffer)
	} else if setup.recipient() == usb_REQUEST_RECIPIENT_INTERFACE {
		device.handleInterfaceRequest(setup, transferBuffer)
	} else {
		panic(fmt.Sprintf("Invalid CMD_SUBMIT recipient: %d", setup.recipient()))
	}
}

func (device *usbDeviceImpl) handleInputMessage(setup usbSetupPacket, transferBuffer []byte) {
	usbLogger.Printf("INPUT TRANSFER BUFFER: %#v\n\n", transferBuffer)
	go device.ctapHIDServer.handleMessage(transferBuffer)
}

func (device *usbDeviceImpl) handleOutputMessage(id uint32, setup usbSetupPacket, transferBuffer []byte, onFinish func()) {
	// Only process one output message at a time in order to maintain message order
	device.outputLock.Lock()
	response := device.ctapHIDServer.getResponse(id, 1000)
	if response != nil {
		copy(transferBuffer, response)
		onFinish()
	}
	device.outputLock.Unlock()
}

func (device *usbDeviceImpl) removeWaitingRequest(id uint32) bool {
	return device.ctapHIDServer.removeWaitingRequest(id)
}

func (device *usbDeviceImpl) handleMessage(id uint32, onFinish func(), endpoint uint32, setup usbSetupPacket, transferBuffer []byte) {
	usbLogger.Printf("USB MESSAGE - ENDPOINT %d\n\n", endpoint)
	if endpoint == 0 {
		device.handleControlMessage(setup, transferBuffer)
		onFinish()
	} else if endpoint == 1 {
		go device.handleOutputMessage(id, setup, transferBuffer, onFinish)
		// handleOutputMessage should handle calling onFinish
	} else if endpoint == 2 {
		device.handleInputMessage(setup, transferBuffer)
		onFinish()
	} else {
		panic(fmt.Sprintf("Invalid USB endpoint: %d", endpoint))
	}
}
