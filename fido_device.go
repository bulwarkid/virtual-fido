package main

import (
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
	}
}

func (device *FIDODevice) getDescriptor(descriptorType uint16) []byte {
	switch descriptorType {
	case USB_DESCRIPTOR_DEVICE:
		return toLE(device.getDeviceDescriptor())
	case USB_DESCRIPTOR_CONFIGURATION:
		return toLE(device.getConfigurationDescriptor())
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
		Busnum:              33,
		Devnum:              22,
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
