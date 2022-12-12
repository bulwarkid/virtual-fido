package usbip

import (
	"bytes"
	"fmt"

	"github.com/bulwarkid/virtual-fido/virtual_fido/util"
)

const (
	usbip_VERSION = 0x0111

	usbip_COMMAND_SUBMIT     = 0x1
	usbip_COMMAND_UNLINK     = 0x2
	usbip_COMMAND_RET_SUBMIT = 0x3
	usbip_COMMAND_RET_UNLINK = 0x4

	usbip_DIR_OUT = 0x0
	usbip_DIR_IN  = 0x1
)

type usbipControlCommand uint16

const (
	usbip_COMMAND_OP_REQ_DEVLIST usbipControlCommand = 0x8005
	usbip_COMMAND_OP_REP_DEVLIST usbipControlCommand = 0x0005
	usbip_COMMAND_OP_REQ_IMPORT  usbipControlCommand = 0x8003
	usbip_COMMAND_OP_REP_IMPORT  usbipControlCommand = 0x0003
)

var usbipControlCommandDescriptions = map[usbipControlCommand]string{
	usbip_COMMAND_OP_REQ_DEVLIST: "usbip_COMMAND_OP_REQ_DEVLIST",
	usbip_COMMAND_OP_REP_DEVLIST: "usbip_COMMAND_OP_REP_DEVLIST",
	usbip_COMMAND_OP_REQ_IMPORT:  "usbip_COMMAND_OP_REQ_IMPORT",
	usbip_COMMAND_OP_REP_IMPORT:  "usbip_COMMAND_OP_REP_IMPORT",
}

func commandString(command uint32) string {
	switch command {
	case usbip_COMMAND_SUBMIT:
		return "usbip_COMMAND_SUBMIT"
	case usbip_COMMAND_UNLINK:
		return "usbip_COMMAND_UNLINK"
	case usbip_COMMAND_RET_SUBMIT:
		return "usbip_COMMAND_RET_SUBMIT"
	case usbip_COMMAND_RET_UNLINK:
		return "usbip_COMMAND_RET_UNLINK"
	default:
		panic(fmt.Sprintf("Unrecognized command: %d", command))
	}
}

type usbipControlHeader struct {
	Version     uint16
	CommandCode usbipControlCommand
	Status      uint32
}

func (header *usbipControlHeader) String() string {
	commandDesc, ok := usbipControlCommandDescriptions[usbipControlCommand(header.CommandCode)]
	if !ok {
		commandDesc = fmt.Sprintf("0x%x", header.CommandCode)
	}
	return fmt.Sprintf("usbipControlHeader{ Version: 0x%04x, Command: %s, Status: 0x%08x }", header.Version, commandDesc, header.Status)
}

type usbipOpRepDevlist struct {
	Header     usbipControlHeader
	NumDevices uint32
	Devices    []usbipDeviceSummary
}

func newOpRepDevlist(device usbDevice) usbipOpRepDevlist {
	return usbipOpRepDevlist{
		Header: usbipControlHeader{
			Version:     usbip_VERSION,
			CommandCode: usbip_COMMAND_OP_REP_DEVLIST,
			Status:      0,
		},
		NumDevices: 1,
		Devices: []usbipDeviceSummary{
			device.usbipSummary(),
		},
	}
}

type usbipOpRepImport struct {
	header usbipControlHeader
	device usbipDeviceSummaryHeader
}

func (reply usbipOpRepImport) String() string {
	return fmt.Sprintf("USBIPOpRepImport{ Header: %#v, Device: %s }", reply.header, reply.device)
}

func newOpRepImport(device usbDevice) usbipOpRepImport {
	return usbipOpRepImport{
		header: usbipControlHeader{
			Version:     usbip_VERSION,
			CommandCode: usbip_COMMAND_OP_REP_IMPORT,
			Status:      0,
		},
		device: device.usbipSummaryHeader(),
	}
}

type usbipMessageHeader struct {
	Command        uint32
	SequenceNumber uint32
	DeviceId       uint32
	Direction      uint32
	Endpoint       uint32
}

func (header usbipMessageHeader) String() string {
	deviceID := fmt.Sprintf("%d-%d", header.DeviceId>>16, header.DeviceId&0xFF)
	return fmt.Sprintf(
		"USBIPMessageHeader{ Command: %v, SequenceNumber: %d, DeviceID: %v, Direction: %v, Endpoint: %d }",
		header.CommandName(),
		header.SequenceNumber,
		deviceID,
		header.DirectionName(),
		header.Endpoint)
}

func (header usbipMessageHeader) CommandName() string {
	return commandString(header.Command)
}

func (header usbipMessageHeader) DirectionName() string {
	var direction string
	if header.Direction == usbip_DIR_IN {
		direction = "usbip_DIR_IN"
	} else {
		direction = "usbip_DIR_OUT"
	}
	return direction
}

type usbipCommandSubmitBody struct {
	TransferFlags        uint32
	TransferBufferLength uint32
	StartFrame           uint32
	NumberOfPackets      uint32
	Interval             uint32
	SetupBytes           [8]byte
}

func (body usbipCommandSubmitBody) String() string {
	return fmt.Sprintf("USBIPCommandSubmitBody{ TransferFlags: 0x%x, TransferBufferLength: %d, StartFrame: %d, NumberOfPackets: %d, Interval: %d, Setup: %s }",
		body.TransferFlags,
		body.TransferBufferLength,
		body.StartFrame,
		body.NumberOfPackets,
		body.Interval,
		body.Setup())
}

func (body usbipCommandSubmitBody) Setup() usbSetupPacket {
	return util.ReadLE[usbSetupPacket](bytes.NewBuffer(body.SetupBytes[:]))
}

type usbipCommandUnlinkBody struct {
	UnlinkSequenceNumber uint32
	Padding              [24]byte
}

type usbipReturnSubmitBody struct {
	Status          uint32
	ActualLength    uint32
	StartFrame      uint32
	NumberOfPackets uint32
	ErrorCount      uint32
	Padding         uint64
}

type usbipReturnUnlinkBody struct {
	Status  int32
	Padding [24]byte
}

type usbipDeviceSummary struct {
	Header          usbipDeviceSummaryHeader
	DeviceInterface usbipDeviceInterface // We only support one interface to use binary.Write/Read
}

func (summary usbipDeviceSummary) String() string {
	return fmt.Sprintf("USBIPDeviceSummary{ Header: %s, DeviceInterface: %#v }", summary.Header, summary.DeviceInterface)
}

type usbipDeviceSummaryHeader struct {
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

func (header usbipDeviceSummaryHeader) String() string {
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

type usbipDeviceInterface struct {
	BInterfaceClass    uint8
	BInterfaceSubclass uint8
	Padding            uint8
}
