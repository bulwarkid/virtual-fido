package usbip

import (
	"fmt"

	"github.com/bulwarkid/virtual-fido/virtual_fido/util"
)

type dummyUSBDevice struct{}

func (device *dummyUSBDevice) removeWaitingRequest(id uint32) bool {
	return false
}

func (device *dummyUSBDevice) usbipSummary() usbipDeviceSummary {
	return usbipDeviceSummary{
		Header:          device.usbipSummaryHeader(),
		DeviceInterface: device.usbipInterfacesSummary(),
	}
}

func (device *dummyUSBDevice) usbipInterfacesSummary() usbipDeviceInterface {
	return usbipDeviceInterface{
		BInterfaceClass:    3,
		BInterfaceSubclass: 0,
		Padding:            0,
	}
}

func (device *dummyUSBDevice) usbipSummaryHeader() usbipDeviceSummaryHeader {
	path := [256]byte{}
	copy(path[:], []byte("/device/0"))
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

func (device *dummyUSBDevice) getDescriptor(descriptorType usbDescriptorType, index uint8) []byte {
	switch descriptorType {
	case usb_DESCRIPTOR_DEVICE:
		descriptor := usbDeviceDescriptor{
			BLength:            util.SizeOf[usbDeviceDescriptor](),
			BDescriptorType:    usb_DESCRIPTOR_DEVICE,
			BcdUSB:             0x0110,
			BDeviceClass:       0,
			BDeviceSubclass:    0,
			BDeviceProtocol:    0,
			BMaxPacketSize:     64,
			IdVendor:           0,
			IdProduct:          0,
			BcdDevice:          0x1,
			IManufacturer:      0,
			IProduct:           0,
			ISerialNumber:      0,
			BNumConfigurations: 0,
		}
		return util.ToLE(descriptor)
	case usb_DESCRIPTOR_CONFIGURATION:
		totalLength := uint16(util.SizeOf[usbConfigurationDescriptor]())
		descriptor := usbConfigurationDescriptor{
			BLength:             util.SizeOf[usbConfigurationDescriptor](),
			BDescriptorType:     usb_DESCRIPTOR_CONFIGURATION,
			WTotalLength:        totalLength,
			BNumInterfaces:      0,
			BConfigurationValue: 0,
			IConfiguration:      0,
			BmAttributes:        usb_CONFIG_ATTR_BASE | usb_CONFIG_ATTR_SELF_POWERED,
			BMaxPower:           0,
		}
		return util.ToLE(descriptor)
	default:
		panic(fmt.Sprintf("Invalid Descriptor type: %d", descriptorType))
	}
}

func (device *dummyUSBDevice) handleControlMessage(setup usbSetupPacket, transferBuffer []byte) {
	switch setup.BRequest {
	case usb_REQUEST_GET_DESCRIPTOR:
		descriptorType, descriptorIndex := getDescriptorTypeAndIndex(setup.WValue)
		descriptor := device.getDescriptor(descriptorType, descriptorIndex)
		copy(transferBuffer, descriptor)
	case usb_REQUEST_SET_CONFIGURATION:
		//fmt.Printf("SET_CONFIGURATION: No-op\n\n")
		// TODO: Handle configuration changes
		// No-op since we can't change configuration
		return
	case usb_REQUEST_GET_STATUS:
		copy(transferBuffer, []byte{1})
	case usb_REQUEST_SET_INTERFACE:
		return
	default:
		panic(fmt.Sprintf("Invalid CMD_SUBMIT bRequest: %d", setup.BRequest))
	}
}

func (device *dummyUSBDevice) handleMessage(id uint32, onFinish func(), endpoint uint32, setup usbSetupPacket, transferBuffer []byte) {
	fmt.Printf("DUMMY USB: %s\n\n", setup)
	if endpoint == 0 {
		device.handleControlMessage(setup, transferBuffer)
		onFinish()
	} else {
		panic(fmt.Sprintf("Invalid USB endpoint: %d", endpoint))
	}
}
