package usbip

import (
	"fmt"
)

const (
	usbipVersion = 0x0111
)

type usbipDirection uint32

const (
	usbipDirOut usbipDirection = 0x0
	usbipDirIn  usbipDirection = 0x1
)

var usbipDirectionDescriptions = map[usbipDirection]string{
	usbipDirOut: "usbipDirOut",
	usbipDirIn: "usbipDirIn",
}

type usbipControlCommand uint16

const (
	usbipCommandOpReqDevlist usbipControlCommand = 0x8005
	usbipCommandOpRepDevlist usbipControlCommand = 0x0005
	usbipCommandOpReqImport  usbipControlCommand = 0x8003
	usbipCommandOpRepImport  usbipControlCommand = 0x0003
)

var usbipControlCommandDescriptions = map[usbipControlCommand]string{
	usbipCommandOpReqDevlist: "usbipCommandOpReqDevlist",
	usbipCommandOpRepDevlist: "usbipCommandOpRepDevlist",
	usbipCommandOpReqImport:  "usbipCommandOpReqImport",
	usbipCommandOpRepImport:  "usbipCommandOpRepImport",
}

type usbipCommand uint32

const (
	usbipCmdSubmit usbipCommand = 0x1
	usbipCmdUnlink usbipCommand = 0x2
	usbipRetSubmit usbipCommand = 0x3
	usbipRetUnlink usbipCommand = 0x4
)

var usbipCommandDescriptions = map[usbipCommand]string{
	usbipCmdSubmit: "usbipCmdSubmit",
	usbipCmdUnlink: "usbipCmdUnlink",
	usbipRetSubmit: "usbipRetSubmit",
	usbipRetUnlink: "usbipRetUnlink",
}

type usbipControlHeader struct {
	Version     uint16
	Command usbipControlCommand
	Status      uint32
}

func (header *usbipControlHeader) String() string {
	commandDesc, ok := usbipControlCommandDescriptions[usbipControlCommand(header.Command)]
	if !ok {
		commandDesc = fmt.Sprintf("0x%x", header.Command)
	}
	return fmt.Sprintf("USBIPControlHeader{ Version: 0x%04x, Command: %s, Status: 0x%08x }", header.Version, commandDesc, header.Status)
}

type usbipOpRepDevlist struct {
	Header     usbipControlHeader
	NumDevices uint32
	Devices    []USBIPDeviceSummary
}

func newOpRepDevlist(devices []USBIPDevice) usbipOpRepDevlist {
	summaries := make([]USBIPDeviceSummary, len(devices))
	for i := range devices {
		summaries[i] = devices[i].DeviceSummary()
	}
	return usbipOpRepDevlist{
		Header: usbipControlHeader{
			Version:     usbipVersion,
			Command: usbipCommandOpRepDevlist,
			Status:      0,
		},
		NumDevices: uint32(len(devices)),
		Devices:    summaries,
	}
}

type usbipOpRepImport struct {
	Header usbipControlHeader
	Device USBIPDeviceSummaryHeader
}

func (reply usbipOpRepImport) String() string {
	return fmt.Sprintf("USBIPOpRepImport{ Header: %#v, Device: %s }", reply.Header, reply.Device)
}

func newOpRepImport(device USBIPDevice) usbipOpRepImport {
	return usbipOpRepImport{
		Header: usbipControlHeader{
			Version:     usbipVersion,
			Command: usbipCommandOpRepImport,
			Status:      0,
		},
		Device: device.DeviceSummary().Header,
	}
}

func opRepImportError(statusCode uint32) usbipControlHeader {
	return usbipControlHeader{
		Version:     usbipVersion,
		Command: usbipCommandOpRepImport,
		Status:      statusCode,
	}
}

type usbipMessageHeader struct {
	Command        usbipCommand
	SequenceNumber uint32
	DeviceID       uint32
	Direction      usbipDirection
	Endpoint       uint32
}

func (header usbipMessageHeader) String() string {
	deviceID := fmt.Sprintf("%d-%d", header.DeviceID>>16, header.DeviceID&0xFF)
	return fmt.Sprintf(
		"USBIPMessageHeader{ Command: %v, SequenceNumber: %d, DeviceID: %v, Direction: %v, Endpoint: %d }",
		usbipCommandDescriptions[header.Command],
		header.SequenceNumber,
		deviceID,
		usbipDirectionDescriptions[header.Direction],
		header.Endpoint)
}

func (header usbipMessageHeader) replyHeader() usbipMessageHeader {
	var command usbipCommand
	switch header.Command {
	case usbipCmdSubmit:
		command = usbipRetSubmit
	case usbipCmdUnlink:
		command = usbipRetUnlink
	}
	return usbipMessageHeader{
		Command:        command,
		SequenceNumber: header.SequenceNumber,
		DeviceID:       0,
		Direction:      0,
		Endpoint:       0,
	}
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
	return fmt.Sprintf("USBIPCommandSubmitBody{ TransferFlags: 0x%x, TransferBufferLength: %d, StartFrame: %d, NumberOfPackets: %d, Interval: %d, Setup: %#v }",
		body.TransferFlags,
		body.TransferBufferLength,
		body.StartFrame,
		body.NumberOfPackets,
		body.Interval,
		body.SetupBytes)
}

type usbipReturnSubmitBody struct {
	Status          uint32
	ActualLength    uint32
	StartFrame      uint32
	NumberOfPackets uint32
	ErrorCount      uint32
	Padding         uint64
}

type usbipCommandUnlinkBody struct {
	UnlinkSequenceNumber uint32
	Padding              [24]byte
}

type usbipReturnUnlinkBody struct {
	Status  int32
	Padding [24]byte
}

type USBIPDeviceSummary struct {
	Header          USBIPDeviceSummaryHeader
	DeviceInterface USBIPDeviceInterface // We only support one interface to use binary.Write/Read
}

func (summary USBIPDeviceSummary) String() string {
	return fmt.Sprintf("USBIPDeviceSummary{ Header: %s, DeviceInterface: %#v }", summary.Header, summary.DeviceInterface)
}

type USBIPDeviceSummaryHeader struct {
	Path                [256]byte // Path on host system
	BusID               [32]byte  // Bus ID on host system
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
		string(header.BusID[:]),
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

type USBIPDevice interface {
	HandleMessage(id uint32, onFinish func(response []byte), endpoint uint32, setupBytes []byte, transferBuffer []byte)
	RemoveWaitingRequest(id uint32) bool
	BusID() string
	DeviceSummary() USBIPDeviceSummary
}
