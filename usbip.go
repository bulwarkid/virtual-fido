package main

import (
	"bytes"
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
	return fmt.Sprintf("USBIPControlHeader{ Version: 0x%04x, Command: 0x%04x, Status: 0x%08x }", header.Version, header.CommandCode, header.Status)
}

type USBIPOpRepDevlist struct {
	Header     USBIPControlHeader
	NumDevices uint32
	Devices    []USBIPDeviceSummary
}

func newOpRepDevlist(device *USBDevice) USBIPOpRepDevlist {
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

func (reply USBIPOpRepImport) String() string {
	return fmt.Sprintf("USBIPOpRepImport{ Header: %#v, Device: %s }", reply.header, reply.device)
}

func newOpRepImport(device *USBDevice) USBIPOpRepImport {
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
	deviceID := fmt.Sprintf("%d-%d", header.DeviceId>>16, header.DeviceId&0xFF)
	return fmt.Sprintf(
		"USBIPMessageHeader{ Command: %v, SequenceNumber: %d, DeviceID: %v, Direction: %v, Endpoint: %d }",
		header.CommandName(),
		header.SequenceNumber,
		deviceID,
		header.DirectionName(),
		header.Endpoint)
}

func (header USBIPMessageHeader) CommandName() string {
	return commandString(header.Command)
}

func (header USBIPMessageHeader) DirectionName() string {
	var direction string
	if header.Direction == USBIP_DIR_IN {
		direction = "USBIP_DIR_IN"
	} else {
		direction = "USBIP_DIR_OUT"
	}
	return direction
}

type USBIPCommandSubmitBody struct {
	TransferFlags        uint32
	TransferBufferLength uint32
	StartFrame           uint32
	NumberOfPackets      uint32
	Interval             uint32
	SetupBytes           [8]byte
}

func (body USBIPCommandSubmitBody) String() string {
	return fmt.Sprintf("USBIPCommandSubmitBody{ TransferFlags: 0x%x, TransferBufferLength: %d, StartFrame: %d, NumberOfPackets: %d, Interval: %d, Setup: %s }",
		body.TransferFlags,
		body.TransferBufferLength,
		body.StartFrame,
		body.NumberOfPackets,
		body.Interval,
		body.Setup())
}

func (body USBIPCommandSubmitBody) Setup() USBSetupPacket {
	return readLE[USBSetupPacket](bytes.NewBuffer(body.SetupBytes[:]))
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

func newReturnSubmit(senderHeader USBIPMessageHeader, command USBIPCommandSubmitBody, data []byte) (USBIPMessageHeader, USBIPReturnSubmitBody) {
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
		StartFrame:      0,
		NumberOfPackets: 0,
		ErrorCount:      0,
		Padding:         0,
	}
	return header, body
}

type USBIPReturnUnlinkBody struct {
	Status  uint32
	Padding [24]byte
}

func newReturnUnlink(senderHeader USBIPMessageHeader) (USBIPMessageHeader, USBIPReturnUnlinkBody) {
	header := USBIPMessageHeader{
		Command:        USBIP_COMMAND_RET_UNLINK,
		SequenceNumber: senderHeader.SequenceNumber,
		DeviceId:       senderHeader.DeviceId,
		Direction:      USBIP_DIR_OUT,
		Endpoint:       senderHeader.Endpoint,
	}
	body := USBIPReturnUnlinkBody{
		Status:  0,
		Padding: [24]byte{},
	}
	return header, body
}

type USBIPDeviceSummary struct {
	Header          USBIPDeviceSummaryHeader
	DeviceInterface USBIPDeviceInterface // We only support one interface to use binary.Write/Read
}

func (summary USBIPDeviceSummary) String() string {
	return fmt.Sprintf("USBIPDeviceSummary{ Header: %s, DeviceInterface: %#v }", summary.Header, summary.DeviceInterface)
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

func (header USBIPDeviceSummaryHeader) String() string {
	return fmt.Sprintf(
		"USBIPDeviceSummaryHeader{ Path: \"%s\", BusId: \"%s\", Busnum: %d, Devnum %d, Speed %d, IdVendor: %d, IdProduct: %d, BcdDevice: 0x%x, BDeviceClass: %d, BDeviceSubclass: %d, BDeviceProtocol: %d, BConfigurationValue: %d, BNumConfigurations: %d, BNumInterfaces: %d}",
		string(header.Path[:]),
		string(header.BusId[:]),
		header.Busnum,
		header.Devnum,
		header.Speed,
		header.IdVendor,
		header.IdProduct,
		header.BcdDevice,
		header.BDeviceClass,
		header.BDeviceSubclass,
		header.BDeviceProtocol,
		header.BConfigurationValue,
		header.BNumConfigurations,
		header.BNumInterfaces)
}

type USBIPDeviceInterface struct {
	BInterfaceClass    uint8
	BInterfaceSubclass uint8
	Padding            uint8
}
