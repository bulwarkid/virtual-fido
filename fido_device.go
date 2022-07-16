package main

import (
	"bytes"
	"fmt"
	"unsafe"
)

type FIDODevice struct {
	Index int
}

func (device *FIDODevice) getDeviceDescriptor() USBDeviceDescriptor {
	length := uint8(unsafe.Sizeof(USBDeviceDescriptor{}))
	return USBDeviceDescriptor{
		BLength:            length,
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
	length := uint8(unsafe.Sizeof(USBConfigurationDescriptor{}))
	totalLength := uint16(unsafe.Sizeof(USBConfigurationDescriptor{}) + unsafe.Sizeof(USBInterfaceDescriptor{}) + unsafe.Sizeof(USBHIDDescriptor{}))
	return USBConfigurationDescriptor{
		BLength:             length,
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
	length := uint8(unsafe.Sizeof(USBInterfaceDescriptor{}))
	return USBInterfaceDescriptor{
		BLength:            length,
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
	length := uint8(unsafe.Sizeof(USBHIDDescriptor{}))
	return USBHIDDescriptor{
		BLength:                 length,
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
	length := uint8(unsafe.Sizeof(USBEndpointDescriptor{}))
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

func (device *FIDODevice) getStringDescriptor(index uint16) []byte {
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

func (device *FIDODevice) getDescriptor(descriptorType uint16, index uint16) []byte {
	switch descriptorType {
	case USB_DESCRIPTOR_DEVICE:
		return toLE(device.getDeviceDescriptor())
	case USB_DESCRIPTOR_CONFIGURATION:
		hidReport := device.getHIDReport()
		buffer := new(bytes.Buffer)
		buffer.Write(toLE(device.getConfigurationDescriptor()))
		buffer.Write(toLE(device.getInterfaceDescriptor()))
		buffer.Write(toLE(device.getHIDDescriptor(hidReport)))
		endpoints := device.getEndpointDescriptors()
		for _, endpoint := range endpoints {
			buffer.Write(toLE(endpoint))
		}
		return buffer.Bytes()
	case USB_DESCRIPTOR_STRING:
		var message []byte
		if index == 0 {
			message = toLE[uint16](0x0409)
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
		fmt.Printf("STRING: %#v %s %v\n", header, message, buffer.Bytes())
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
