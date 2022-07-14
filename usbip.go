package main

import (
	"fmt"
)

const (
	USBIP_VERSION = 0x0111

	USBIP_COMMAND_OP_REQ_DEVLIST = 0x8005
	USBIP_COMMAND_OP_REP_DEVLIST = 0x0005
	USBIP_COMMAND_OP_REQ_IMPORT  = 0x8003
	USBIP_COMMAND_OP_REP_IMPORT  = 0x0003

	USBIP_COMMAND_SUBMIT     = 0x1
	USBIP_COMMAND_UNLINK     = 0x2
	USBIP_COMMAND_RET_SUBMIT = 0x3
	USBIP_COMMAND_RET_UNLINK = 0x4

	USBIP_DIR_OUT = 0x0
	USBIP_DIR_IN  = 0x1
)

func commandString(command uint32) string {
	switch command {
	case USBIP_COMMAND_SUBMIT:
		return "USBIP_COMMAND_SUBMIT"
	case USBIP_COMMAND_UNLINK:
		return "USBIP_COMMAND_UNLINK"
	case USBIP_COMMAND_RET_SUBMIT:
		return "USBIP_COMMAND_RET_SUBMIT"
	case USBIP_COMMAND_RET_UNLINK:
		return "USBIP_COMMAND_RET_UNLINK"
	default:
		panic(fmt.Sprintf("Unrecognized command: %d", command))
	}
}

type USBIPControlHeader struct {
	Version     uint16
	CommandCode uint16
	Status      uint32
}

func (header *USBIPControlHeader) String() string {
	return fmt.Sprintf("USBIPHeader{ Version: 0x%04x, Command: 0x%04x, Status: 0x%08x }", header.Version, header.CommandCode, header.Status)
}

type USBIPOpRepDevlist struct {
	Header     USBIPControlHeader
	NumDevices uint32
	Devices    []USBIPDeviceSummary
}

func newOpRepDevlist(device *FIDODevice) USBIPOpRepDevlist {
	return USBIPOpRepDevlist{
		Header: USBIPControlHeader{
			Version:     USBIP_VERSION,
			CommandCode: USBIP_COMMAND_OP_REP_DEVLIST,
			Status:      0,
		},
		NumDevices: 1,
		Devices: []USBIPDeviceSummary{
			device.usbipSummary(),
		},
	}
}

type USBIPOpRepImport struct {
	header USBIPControlHeader
	device USBIPDeviceSummaryHeader
}

func newOpRepImport(device *FIDODevice) USBIPOpRepImport {
	return USBIPOpRepImport{
		header: USBIPControlHeader{
			Version:     USBIP_VERSION,
			CommandCode: USBIP_COMMAND_OP_REP_IMPORT,
			Status:      0,
		},
		device: device.usbipSummaryHeader(),
	}
}

type USBIPMessageHeader struct {
	Command        uint32
	SequenceNumber uint32
	DeviceId       uint32
	Direction      uint32
	Endpoint       uint32
}

func (header USBIPMessageHeader) String() string {
	var direction string
	if header.Direction == USBIP_DIR_IN {
		direction = "USBIP_DIR_IN"
	} else {
		direction = "USBIP_DIR_OUT"
	}
	deviceID := fmt.Sprintf("%d-%d", header.DeviceId>>16, header.DeviceId&0xFF)
	return fmt.Sprintf(
		"USBIPMessageHeader{ Command: %v, SequenceNumber: %d, DeviceID: %v, Direction: %v, Endpoint: %d }",
		commandString(header.Command),
		header.SequenceNumber,
		deviceID,
		direction,
		header.Endpoint)
}

type USBIPCommandSubmitBody struct {
	TransferFlags        uint32
	TransferBufferLength uint32
	StartFrame           uint32
	NumberOfPackets      uint32
	Interval             uint32
	Setup                [8]byte
}

type USBIPCommandUnlinkBody struct {
	UnlinkSequenceNumber uint32
	Padding              [24]byte
}

type USBIPReturnSubmitBody struct {
	Status          uint32
	ActualLength    uint32
	StartFrame      uint32
	NumberOfPackets uint32
	ErrorCount      uint32
	Padding         uint64
}

func newReturnSubmit(senderHeader USBIPMessageHeader, command USBIPCommandSubmitBody, data []byte) (USBIPMessageHeader, USBIPReturnSubmitBody, error) {
	header := USBIPMessageHeader{
		Command:        USBIP_COMMAND_RET_SUBMIT,
		SequenceNumber: senderHeader.SequenceNumber,
		DeviceId:       senderHeader.DeviceId,
		Direction:      USBIP_DIR_OUT,
		Endpoint:       senderHeader.Endpoint,
	}
	body := USBIPReturnSubmitBody{
		Status:          0,
		ActualLength:    uint32(len(data)),
		StartFrame:      command.StartFrame,
		NumberOfPackets: command.NumberOfPackets,
		ErrorCount:      0,
		Padding:         0,
	}
	return header, body, nil
}

type USBIPDeviceSummary struct {
	Header          USBIPDeviceSummaryHeader
	DeviceInterface USBIPDeviceInterface // We only support one interface to use binary.Write/Read
}

type USBIPDeviceSummaryHeader struct {
	Path                [256]byte
	BusId               [32]byte
	Busnum              uint32
	Devnum              uint32
	Speed               uint32
	IdVendor            uint16
	IdProduct           uint16
	BcdDevice           uint16
	BDeviceClass        uint8
	BDeviceSubclass     uint8
	BDeviceProtocol     uint8
	BConfigurationValue uint8
	BNumConfigurations  uint8
	BNumInterfaces      uint8
}

type USBIPDeviceInterface struct {
	BInterfaceClass    uint8
	BInterfaceSubclass uint8
	Padding            uint8
}
