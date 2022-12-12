package usbip

import (
	"fmt"

	"github.com/bulwarkid/virtual-fido/util"
)

type DummyUSBDevice struct{}

func (device *DummyUSBDevice) removeWaitingRequest(id uint32) bool {
	return false
}

func (device *DummyUSBDevice) usbipSummary() USBIPDeviceSummary {
	return USBIPDeviceSummary{
		Header:          device.usbipSummaryHeader(),
		DeviceInterface: device.usbipInterfacesSummary(),
	}
}

func (device *DummyUSBDevice) usbipInterfacesSummary() USBIPDeviceInterface {
	return USBIPDeviceInterface{
		BInterfaceClass:    3,
		BInterfaceSubclass: 0,
		Padding:            0,
	}
}

func (device *DummyUSBDevice) usbipSummaryHeader() USBIPDeviceSummaryHeader {
	path := [256]byte{}
	copy(path[:], []byte("/device/0"))
	busId := [32]byte{}
	copy(busId[:], []byte("2-2"))
	return USBIPDeviceSummaryHeader{
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

func (device *DummyUSBDevice) getDescriptor(descriptorType USBDescriptorType, index uint8) []byte {
	switch descriptorType {
	case USB_DESCRIPTOR_DEVICE:
		descriptor := USBDeviceDescriptor{
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
			IManufacturer:      0,
			IProduct:           0,
			ISerialNumber:      0,
			BNumConfigurations: 0,
		}
		return util.ToLE(descriptor)
	case USB_DESCRIPTOR_CONFIGURATION:
		totalLength := uint16(util.SizeOf[USBConfigurationDescriptor]())
		descriptor := USBConfigurationDescriptor{
			BLength:             util.SizeOf[USBConfigurationDescriptor](),
			BDescriptorType:     USB_DESCRIPTOR_CONFIGURATION,
			WTotalLength:        totalLength,
			BNumInterfaces:      0,
			BConfigurationValue: 0,
			IConfiguration:      0,
			BmAttributes:        USB_CONFIG_ATTR_BASE | USB_CONFIG_ATTR_SELF_POWERED,
			BMaxPower:           0,
		}
		return util.ToLE(descriptor)
	default:
		panic(fmt.Sprintf("Invalid Descriptor type: %d", descriptorType))
	}
}

func (device *DummyUSBDevice) handleControlMessage(setup USBSetupPacket, transferBuffer []byte) {
	switch setup.BRequest {
	case USB_REQUEST_GET_DESCRIPTOR:
		descriptorType, descriptorIndex := getDescriptorTypeAndIndex(setup.WValue)
		descriptor := device.getDescriptor(descriptorType, descriptorIndex)
		copy(transferBuffer, descriptor)
	case USB_REQUEST_SET_CONFIGURATION:
		//fmt.Printf("SET_CONFIGURATION: No-op\n\n")
		// TODO: Handle configuration changes
		// No-op since we can't change configuration
		return
	case USB_REQUEST_GET_STATUS:
		copy(transferBuffer, []byte{1})
	case USB_REQUEST_SET_INTERFACE:
		return
	default:
		panic(fmt.Sprintf("Invalid CMD_SUBMIT bRequest: %d", setup.BRequest))
	}
}

func (device *DummyUSBDevice) handleMessage(id uint32, onFinish func(), endpoint uint32, setup USBSetupPacket, transferBuffer []byte) {
	fmt.Printf("DUMMY USB: %s\n\n", setup)
	if endpoint == 0 {
		device.handleControlMessage(setup, transferBuffer)
		onFinish()
	} else {
		panic(fmt.Sprintf("Invalid USB endpoint: %d", endpoint))
	}
}
