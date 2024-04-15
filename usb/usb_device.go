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
	delegate USBDeviceDelegate
	outputLock    sync.Locker
}

func NewUSBDevice(delegate USBDeviceDelegate) *USBDevice {
	return &USBDevice{
		delegate: delegate,
		outputLock:    &sync.Mutex{},
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
	setup := util.ReadBE[USBSetupPacket](bytes.NewBuffer(setupBytes[:]))
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

func (device *USBDevice) handleControlMessage(setup USBSetupPacket, transferBuffer []byte) {
	usbLogger.Printf("CONTROL MESSAGE: %s\n\n", setup)
	if setup.direction() == USB_HOST_TO_DEVICE {
		usbLogger.Printf("TRANSFER BUFFER: %v\n\n", transferBuffer)
	}
	if setup.recipient() == USB_REQUEST_RECIPIENT_DEVICE {
		device.handleDeviceRequest(setup, transferBuffer)
	} else if setup.recipient() == USB_REQUEST_RECIPIENT_INTERFACE {
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

func (device *USBDevice) handleDeviceRequest(setup USBSetupPacket, transferBuffer []byte) {
	switch setup.BRequest {
	case USB_REQUEST_GET_DESCRIPTOR:
		descriptorType, descriptorIndex := getDescriptorTypeAndIndex(setup.WValue)
		descriptor := device.getDescriptor(descriptorType, descriptorIndex)
		copy(transferBuffer, descriptor)
	case USB_REQUEST_SET_CONFIGURATION:
		usbLogger.Printf("SET_CONFIGURATION: No-op\n\n")
		// TODO: Handle configuration changes
		// No-op since we can't change configuration
		return
	case USB_REQUEST_GET_STATUS:
		copy(transferBuffer, []byte{1})
	default:
		util.Panic(fmt.Sprintf("Invalid CMD_SUBMIT bRequest: %d", setup.BRequest))
	}
}

func (device *USBDevice) handleInterfaceRequest(setup USBSetupPacket, transferBuffer []byte) {
	switch USBHIDRequestType(setup.BRequest) {
	case USB_HID_REQUEST_SET_IDLE:
		// No-op since we are made in software
		usbLogger.Printf("SET IDLE: No-op\n\n")
	case USB_HID_REQUEST_SET_PROTOCOL:
		// No-op since we are always in report protocol, no boot protocol
	case USB_HID_REQUEST_GET_DESCRIPTOR:
		descriptorType, descriptorIndex := getDescriptorTypeAndIndex(setup.WValue)
		usbLogger.Printf("GET INTERFACE DESCRIPTOR: Type: %s Index: %d\n\n", descriptorTypeDescriptions[descriptorType], descriptorIndex)
		switch descriptorType {
		case USB_DESCRIPTOR_HID_REPORT:
			usbLogger.Printf("HID REPORT: %v\n\n", device.getHIDReport())
			copy(transferBuffer, device.getHIDReport())
		default:
			util.Panic(fmt.Sprintf("Invalid USB Interface descriptor: %d - %d", descriptorType, descriptorIndex))
		}
	default:
		util.Panic(fmt.Sprintf("Invalid USB Interface bRequest: %d", setup.BRequest))
	}
}

func (device *USBDevice) getDescriptor(descriptorType USBDescriptorType, index uint8) []byte {
	usbLogger.Printf("GET DESCRIPTOR: Type: %s Index: %d\n\n", descriptorTypeDescriptions[descriptorType], index)
	switch descriptorType {
	case USB_DESCRIPTOR_DEVICE:
		descriptor := device.getDeviceDescriptor()
		usbLogger.Printf("DEVICE DESCRIPTOR: %#v\n\n", descriptor)
		return util.ToLE(descriptor)
	case USB_DESCRIPTOR_CONFIGURATION:
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
	case USB_DESCRIPTOR_STRING:
		message := device.getStringDescriptor(index)
		header := USBStringDescriptorHeader{
			BLength:         0,
			BDescriptorType: USB_DESCRIPTOR_STRING,
		}
		header.BLength = uint8(unsafe.Sizeof(header)) + uint8(len(message))
		usbLogger.Printf("STRING: Length: %d Message: \"%s\" Bytes: %v\n\n", header.BLength, message, message)
		return util.Flatten([][]byte{util.ToLE(header), message})
	default:
		util.Panic(fmt.Sprintf("Invalid Descriptor type: %d", descriptorType))
	}
	return nil
}

func (device *USBDevice) getDeviceDescriptor() USBDeviceDescriptor {
	return USBDeviceDescriptor{
		BLength:            util.SizeOf[USBDeviceDescriptor](),
		BDescriptorType:    USB_DESCRIPTOR_DEVICE,
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

func (device *USBDevice) getConfigurationDescriptor(configLength uint16) USBConfigurationDescriptor {
	totalLength := uint16(util.SizeOf[USBConfigurationDescriptor]()) + configLength
	return USBConfigurationDescriptor{
		BLength:             util.SizeOf[USBConfigurationDescriptor](),
		BDescriptorType:     USB_DESCRIPTOR_CONFIGURATION,
		WTotalLength:        totalLength,
		BNumInterfaces:      1,
		BConfigurationValue: 0,
		IConfiguration:      4,
		BmAttributes:        USB_CONFIG_ATTR_BASE | USB_CONFIG_ATTR_SELF_POWERED,
		BMaxPower:           0,
	}
}

func (device *USBDevice) getInterfaceDescriptor() USBInterfaceDescriptor {
	return USBInterfaceDescriptor{
		BLength:            util.SizeOf[USBInterfaceDescriptor](),
		BDescriptorType:    USB_DESCRIPTOR_INTERFACE,
		BInterfaceNumber:   0,
		BAlternateSetting:  0,
		BNumEndpoints:      2,
		BInterfaceClass:    USB_INTERFACE_CLASS_HID,
		BInterfaceSubclass: 0,
		BInterfaceProtocol: 0,
		IInterface:         5,
	}
}

func (device *USBDevice) getHIDDescriptor(hidReportDescriptor []byte) USBHIDDescriptor {
	return USBHIDDescriptor{
		BLength:                 util.SizeOf[USBHIDDescriptor](),
		BDescriptorType:         USB_DESCRIPTOR_HID,
		BcdHID:                  0x0101,
		BCountryCode:            0,
		BNumDescriptors:         1,
		BClassDescriptorType:    USB_DESCRIPTOR_HID_REPORT,
		WReportDescriptorLength: uint16(len(hidReportDescriptor)),
	}
}

func (device *USBDevice) getHIDReport() []byte {
	// Manually calculated using the HID Report calculator for a FIDO device
	return []byte{6, 208, 241, 9, 1, 161, 1, 9, 32, 20, 37, 255, 117, 8, 149, 64, 129, 2, 9, 33, 20, 37, 255, 117, 8, 149, 64, 145, 2, 192}
}

func (device *USBDevice) getEndpointDescriptors() []USBEndpointDescriptor {
	length := util.SizeOf[USBEndpointDescriptor]()
	return []USBEndpointDescriptor{
		{
			BLength:          length,
			BDescriptorType:  USB_DESCRIPTOR_ENDPOINT,
			BEndpointAddress: 0b10000001,
			BmAttributes:     0b00000011,
			WMaxPacketSize:   64,
			BInterval:        255,
		},
		{
			BLength:          length,
			BDescriptorType:  USB_DESCRIPTOR_ENDPOINT,
			BEndpointAddress: 0b00000010,
			BmAttributes:     0b00000011,
			WMaxPacketSize:   64,
			BInterval:        255,
		},
	}
}

func (device *USBDevice) getStringDescriptor(index uint8) []byte {
	switch index {
	case 0:
		return util.ToLE[uint16](USB_LANGID_ENG_USA)
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
