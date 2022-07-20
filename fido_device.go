package main

import (
	"bytes"
	"fmt"
	"unsafe"
)

type FIDODevice struct {
	Index      int
	CTAPServer *CTAPHIDServer
}

func NewFIDODevice(ctapHIDServer *CTAPHIDServer) *FIDODevice {
	return &FIDODevice{
		Index:      0,
		CTAPServer: ctapHIDServer,
	}
}

func (device *FIDODevice) getDeviceDescriptor() USBDeviceDescriptor {
	return USBDeviceDescriptor{
		BLength:            sizeOf[USBDeviceDescriptor](),
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

func (device *FIDODevice) getConfigurationDescriptor() USBConfigurationDescriptor {
	totalLength := uint16(sizeOf[USBConfigurationDescriptor]()) +
		uint16(sizeOf[USBInterfaceDescriptor]()) +
		uint16(sizeOf[USBHIDDescriptor]()) +
		uint16(2*sizeOf[USBEndpointDescriptor]())
	return USBConfigurationDescriptor{
		BLength:             sizeOf[USBConfigurationDescriptor](),
		BDescriptorType:     USB_DESCRIPTOR_CONFIGURATION,
		WTotalLength:        totalLength,
		BNumInterfaces:      1,
		BConfigurationValue: 0,
		IConfiguration:      4,
		BmAttributes:        USB_CONFIG_ATTR_BASE | USB_CONFIG_ATTR_SELF_POWERED,
		BMaxPower:           0,
	}
}

func (device *FIDODevice) getInterfaceDescriptor() USBInterfaceDescriptor {
	return USBInterfaceDescriptor{
		BLength:            sizeOf[USBInterfaceDescriptor](),
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

func (device *FIDODevice) getHIDDescriptor(hidReportDescriptor []byte) USBHIDDescriptor {
	return USBHIDDescriptor{
		BLength:                 sizeOf[USBHIDDescriptor](),
		BDescriptorType:         USB_DESCRIPTOR_HID,
		BcdHID:                  0x0101,
		BCountryCode:            0,
		BNumDescriptors:         1,
		BClassDescriptorType:    USB_DESCRIPTOR_HID_REPORT,
		WReportDescriptorLength: uint16(len(hidReportDescriptor)),
	}
}

func (device *FIDODevice) getHIDReport() []byte {
	// Manually calculated using the HID Report calculator for a FIDO device
	return []byte{6, 208, 241, 9, 1, 161, 1, 9, 32, 20, 37, 255, 117, 8, 149, 64, 129, 2, 9, 33, 20, 37, 255, 117, 8, 149, 64, 145, 2, 192}
}

func (device *FIDODevice) getEndpointDescriptors() []USBEndpointDescriptor {
	length := sizeOf[USBEndpointDescriptor]()
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

func (device *FIDODevice) getStringDescriptor(index uint8) []byte {
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

func (device *FIDODevice) getDescriptor(descriptorType USBDescriptorType, index uint8) []byte {
	fmt.Printf("GET DESCRIPTOR: Type: %s Index: %d\n\n", descriptorTypeDescriptions[descriptorType], index)
	switch descriptorType {
	case USB_DESCRIPTOR_DEVICE:
		descriptor := device.getDeviceDescriptor()
		fmt.Printf("DEVICE DESCRIPTOR: %#v\n\n", descriptor)
		return toLE(descriptor)
	case USB_DESCRIPTOR_CONFIGURATION:
		hidReport := device.getHIDReport()
		buffer := new(bytes.Buffer)
		config := device.getConfigurationDescriptor()
		interfaceDescriptor := device.getInterfaceDescriptor()
		hid := device.getHIDDescriptor(hidReport)
		fmt.Printf("CONFIGURATION: %#v\n\nINTERFACE: %#v\n\nHID: %#v\n\n", config, interfaceDescriptor, hid)
		buffer.Write(toLE(config))
		buffer.Write(toLE(interfaceDescriptor))
		buffer.Write(toLE(hid))
		endpoints := device.getEndpointDescriptors()
		for _, endpoint := range endpoints {
			fmt.Printf("ENDPOINT: %#v\n\n", endpoint)
			buffer.Write(toLE(endpoint))
		}
		return buffer.Bytes()
	case USB_DESCRIPTOR_STRING:
		var message []byte
		if index == 0 {
			message = toLE[uint16](USB_LANGID_ENG_USA)
		} else {
			message = device.getStringDescriptor(index)
		}
		var header USBStringDescriptorHeader
		length := uint8(unsafe.Sizeof(header)) + uint8(len(message))
		header = USBStringDescriptorHeader{
			BLength:         length,
			BDescriptorType: USB_DESCRIPTOR_STRING,
		}
		buffer := new(bytes.Buffer)
		buffer.Write(toLE(header))
		buffer.Write([]byte(message))
		fmt.Printf("STRING: Length: %d Message: \"%s\" Bytes: %v\n\n", header.BLength, message, buffer.Bytes())
		return buffer.Bytes()
	default:
		panic(fmt.Sprintf("Invalid Descriptor type: %d", descriptorType))
	}
}

func (device *FIDODevice) usbipSummary() USBIPDeviceSummary {
	return USBIPDeviceSummary{
		Header:          device.usbipSummaryHeader(),
		DeviceInterface: device.usbipInterfacesSummary(),
	}
}

func (device *FIDODevice) usbipSummaryHeader() USBIPDeviceSummaryHeader {
	path := [256]byte{}
	copy(path[:], []byte("/device/"+fmt.Sprint(device.Index)))
	busId := [32]byte{}
	copy(busId[:], []byte("1-1"))
	return USBIPDeviceSummaryHeader{
		Path:                path,
		BusId:               busId,
		Busnum:              1,
		Devnum:              1,
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

func (device *FIDODevice) usbipInterfacesSummary() USBIPDeviceInterface {
	return USBIPDeviceInterface{
		BInterfaceClass:    3,
		BInterfaceSubclass: 0,
		Padding:            0,
	}
}

func (device *FIDODevice) handleDeviceRequest(
	setup USBSetupPacket,
	transferBuffer []byte) {
	switch setup.BRequest {
	case USB_REQUEST_GET_DESCRIPTOR:
		descriptorType, descriptorIndex := getDescriptorTypeAndIndex(setup.WValue)
		descriptor := device.getDescriptor(descriptorType, descriptorIndex)
		copy(transferBuffer, descriptor)
	case USB_REQUEST_SET_CONFIGURATION:
		fmt.Printf("SET_CONFIGURATION: No-op\n\n")
		// No-op since we can't change configuration
		return
	case USB_REQUEST_GET_STATUS:
		copy(transferBuffer, []byte{1})
	default:
		panic(fmt.Sprintf("Invalid CMD_SUBMIT bRequest: %d", setup.BRequest))
	}
}

func (device *FIDODevice) handleInterfaceRequest(setup USBSetupPacket, transferBuffer []byte) {

	switch USBHIDRequestType(setup.BRequest) {
	case USB_HID_REQUEST_SET_IDLE:
		// No-op since we are made in software
		fmt.Printf("SET IDLE: No-op\n\n")
		return
	case USBHIDRequestType(USB_REQUEST_GET_DESCRIPTOR):
		descriptorType, descriptorIndex := getDescriptorTypeAndIndex(setup.WValue)
		fmt.Printf("GET INTERFACE DESCRIPTOR: Type: %s Index: %d\n\n", descriptorTypeDescriptions[descriptorType], descriptorIndex)
		switch descriptorType {
		case USB_DESCRIPTOR_HID_REPORT:
			fmt.Printf("HID REPORT: %v\n\n", device.getHIDReport())
			copy(transferBuffer, device.getHIDReport())
		default:
			panic(fmt.Sprintf("Invalid USB Interface descriptor: %d - %d", descriptorType, descriptorIndex))
		}
	default:
		panic(fmt.Sprintf("Invalid USB Interface bRequest: %d", setup.BRequest))
	}
}

func (device *FIDODevice) handleControlMessage(setup USBSetupPacket, transferBuffer []byte) {
	if setup.recipient() == USB_REQUEST_RECIPIENT_DEVICE {
		device.handleDeviceRequest(setup, transferBuffer)
	} else if setup.recipient() == USB_REQUEST_RECIPIENT_INTERFACE {
		device.handleInterfaceRequest(setup, transferBuffer)
	} else {
		panic(fmt.Sprintf("Invalid CMD_SUBMIT recipient: %d", setup.recipient()))
	}
}

func (device *FIDODevice) handleInputMessage(setup USBSetupPacket, transferBuffer []byte) {
	buffer := bytes.NewBuffer(transferBuffer)
	device.CTAPServer.handleInputMessage(buffer)
}

func (device *FIDODevice) handleOutputMessage(setup USBSetupPacket, transferBuffer []byte) {
	response := device.CTAPServer.getResponse()
	if response != nil {
		copy(transferBuffer, response)
	}
}

func (device *FIDODevice) handleMessage(endpoint uint32, setup USBSetupPacket, transferBuffer []byte) {
	if endpoint == 0 {
		device.handleControlMessage(setup, transferBuffer)
	} else if endpoint == 1 {
		device.handleOutputMessage(setup, transferBuffer)
	} else if endpoint == 2 {
		device.handleInputMessage(setup, transferBuffer)
	} else {
		panic(fmt.Sprintf("Invalid USB endpoint: %d", endpoint))
	}
}
