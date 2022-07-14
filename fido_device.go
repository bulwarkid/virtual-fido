package main

import "fmt"

type FIDODevice struct{}

func getDeviceDescriptor() USBDeviceDescriptor {
	return USBDeviceDescriptor{
		BLength:            18,
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

func (device *FIDODevice) getDescriptor(descriptorType uint16) ([]byte, error) {
	switch descriptorType {
	case USB_DESCRIPTOR_DEVICE:
		return toLE(getDeviceDescriptor()), nil
	default:
		return nil, fmt.Errorf("Invalid Descriptor type: %d", descriptorType)
	}
}
