package usb

import (
	"bytes"
	"fmt"
	"unsafe"

	"github.com/bulwarkid/virtual-fido/usbip"
	"github.com/bulwarkid/virtual-fido/util"
)

var usbLogger = util.NewLogger("[USB] ", util.LogLevelTrace)

type USBDeviceDelegate interface {
	HandleMessage(transferBuffer []byte)
	SetResponseHandler(handler func(response []byte))
}

type USBDevice struct {
	delegate        USBDeviceDelegate
	requestBuffer *util.RequestBuffer
}

func NewUSBDevice(delegate USBDeviceDelegate) *USBDevice {
	device := &USBDevice{
		delegate:        delegate,
		requestBuffer:   util.MakeRequestBuffer(),
	}
	delegate.SetResponseHandler(func(response []byte) {
		device.handleResponse(response)
	})
	return device
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
	return device.requestBuffer.CancelRequest(id)
}

func (device *USBDevice) HandleMessage(id uint32, onFinish func(response []byte), endpoint uint32, setupBytes []byte, data []byte) {
	setup := util.ReadLE[usbSetupPacket](bytes.NewBuffer(setupBytes))
	usbLogger.Printf("USB MESSAGE - ENDPOINT %d SETUP: %s\n\n", endpoint, setup)
	switch usbEndpoint(endpoint) {
	case usbEndpointControl:
		reply := device.handleControlMessage(setup)
		onFinish(reply)
	case usbEndpointOutput:
		device.requestBuffer.Request(id, onFinish)
		util.SetTimeout(1000, func() {
			// If the request hasn't finished yet, cancel it and return nil
			if device.requestBuffer.CancelRequest(id) {
				onFinish(nil)
			}
		})
		// onFinish will be called when a response is returned
	case usbEndpointInput:
		usbLogger.Printf("INPUT DATA: %#v\n\n", data)
		go device.delegate.HandleMessage(data)
		onFinish(nil)
	default:
		util.Panic(fmt.Sprintf("Invalid USB endpoint: %d", endpoint))
	}
}

func (device *USBDevice) handleResponse(response []byte) {
	device.requestBuffer.Respond(response)
}

func (device *USBDevice) handleControlMessage(setup usbSetupPacket) []byte {
	switch setup.recipient() {
	case usbRequestRecipientDevice:
		return device.handleDeviceRequest(setup)
	case usbRequestRecipientInterface:
		return device.handleInterfaceRequest(setup)
	default:
		util.Panic(fmt.Sprintf("Invalid CMD_SUBMIT recipient: %d", setup.recipient()))
	}
	return nil
}

func (device *USBDevice) handleDeviceRequest(setup usbSetupPacket) []byte {
	switch setup.BRequest {
	case usbRequestGetDescriptor:
		descriptorType, descriptorIndex := getDescriptorTypeAndIndex(setup.WValue)
		return device.getDescriptor(descriptorType, descriptorIndex)
	case usbRequestSetConfiguration:
		usbLogger.Printf("SET_CONFIGURATION: No-op\n\n")
		// TODO: Handle configuration changes
		// No-op since we can't change configuration
		return nil
	case usbRequestGetStatus:
		return []byte{1}
	default:
		util.Panic(fmt.Sprintf("Invalid CMD_SUBMIT bRequest: %d", setup.BRequest))
	}
	return nil
}

func (device *USBDevice) handleInterfaceRequest(setup usbSetupPacket) []byte {
	switch usbHIDRequestType(setup.BRequest) {
	case usbHIDRequestSetIdle:
		// No-op since we are made in software
		usbLogger.Printf("SET IDLE: No-op\n\n")
	case usbHIDRequestSetProtocol:
		// No-op since we are always in report protocol, no boot protocol
	case usbHIDRequestGetDescriptor:
		descriptorType, descriptorIndex := getDescriptorTypeAndIndex(setup.WValue)
		usbLogger.Printf("GET INTERFACE DESCRIPTOR - Type: %s Index: %d\n\n", descriptorType, descriptorIndex)
		switch descriptorType {
		case usbDescriptorHIDReport:
			usbLogger.Printf("HID REPORT: %v\n\n", device.getHIDReport())
			return device.getHIDReport()
		default:
			util.Panic(fmt.Sprintf("Invalid USB Interface descriptor: %d - %d", descriptorType, descriptorIndex))
		}
	default:
		util.Panic(fmt.Sprintf("Invalid USB Interface bRequest: %d", setup.BRequest))
	}
	return nil
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
		return util.Concat(util.ToLE(config), configBytes)
	case usbDescriptorString:
		message := device.getStringDescriptor(index)
		header := usbStringDescriptorHeader{
			BLength:         0,
			BDescriptorType: usbDescriptorString,
		}
		header.BLength = uint8(unsafe.Sizeof(header)) + uint8(len(message))
		usbLogger.Printf("STRING: Length: %d Message: \"%s\" Bytes: %v\n\n", header.BLength, message, message)
		return util.Concat(util.ToLE(header), message)
	default:
		util.Panic(fmt.Sprintf("Invalid Descriptor type: %d", descriptorType))
	}
	return nil
}

func (device *USBDevice) getDeviceDescriptor() usbDeviceDescriptor {
	return usbDeviceDescriptor{
		BLength:            util.SizeOf[usbDeviceDescriptor](),
		BDescriptorType:    usbDescriptorDevice,
		BcdUSB:             0x0110,
		BDeviceClass:       0,
		BDeviceSubclass:    0,
		BDeviceProtocol:    0,
		BMaxPacketSize:     64,
		IDVendor:           0,
		IDProduct:          0,
		BcdDevice:          0x1,
		IManufacturer:      1,
		IProduct:           2,
		ISerialNumber:      3,
		BNumConfigurations: 1,
	}
}

func (device *USBDevice) getConfigurationDescriptor(configLength uint16) usbConfigurationDescriptor {
	totalLength := uint16(util.SizeOf[usbConfigurationDescriptor]()) + configLength
	return usbConfigurationDescriptor{
		BLength:             util.SizeOf[usbConfigurationDescriptor](),
		BDescriptorType:     usbDescriptorConfiguration,
		WTotalLength:        totalLength,
		BNumInterfaces:      1,
		BConfigurationValue: 0,
		IConfiguration:      4,
		BmAttributes:        usbConfigAttributeBase | usbConfigAttributeSelfPowered,
		BMaxPower:           0,
	}
}

func (device *USBDevice) getInterfaceDescriptor() usbInterfaceDescriptor {
	return usbInterfaceDescriptor{
		BLength:            util.SizeOf[usbInterfaceDescriptor](),
		BDescriptorType:    usbDescriptorInterface,
		BInterfaceNumber:   0,
		BAlternateSetting:  0,
		BNumEndpoints:      2,
		BInterfaceClass:    usbInterfaceClassHID,
		BInterfaceSubclass: 0,
		BInterfaceProtocol: 0,
		IInterface:         5,
	}
}

func (device *USBDevice) getHIDDescriptor(hidReportDescriptor []byte) usbHIDDescriptor {
	return usbHIDDescriptor{
		BLength:                 util.SizeOf[usbHIDDescriptor](),
		BDescriptorType:         usbDescriptorHID,
		BcdHID:                  0x0101,
		BCountryCode:            usbHIDCountryCodeNone,
		BNumDescriptors:         1,
		BClassDescriptorType:    usbDescriptorHIDReport,
		WReportDescriptorLength: uint16(len(hidReportDescriptor)),
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
			BLength:          length,
			BDescriptorType:  usbDescriptorEndpoint,
			BEndpointAddress: 0b10000001,
			BmAttributes:     0b00000011,
			WMaxPacketSize:   64,
			BInterval:        255,
		},
		{
			BLength:          length,
			BDescriptorType:  usbDescriptorEndpoint,
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
