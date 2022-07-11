package main

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	USBIP_VERSION = 0x0111

	USBIP_COMMAND_OP_REQ_DEVLIST = 0x8005
	USBIP_COMMAND_OP_REP_DEVLIST = 0x0005
	USBIP_COMMAND_OP_REQ_IMPORT  = 0x8003
	USBIP_COMMAND_OP_REP_IMPORT  = 0x0003

	USBIP_COMMAND
)

type USBIPControlHeader struct {
	Version     uint16
	CommandCode uint16
	Status      uint32
}

func (header *USBIPControlHeader) String() string {
	return fmt.Sprintf("USBIPHeader{ Version: 0x%04x, Command: 0x%04x, Status: 0x%08x }", header.Version, header.CommandCode, header.Status)
}

func readUSBIPHeader(reader io.Reader) (*USBIPControlHeader, error) {
	header := USBIPControlHeader{}
	err := binary.Read(reader, binary.BigEndian, &header)
	if err != nil {
		return nil, fmt.Errorf("Could not read USBIP header: %w", err)
	}
	return &header, nil
}

type USBIPOpRepDevlist struct {
	Header     USBIPControlHeader
	NumDevices uint32
	Devices    []USBDeviceSummary
}

func opRepDevlist() USBIPOpRepDevlist {
	device := USBDevice{}
	return USBIPOpRepDevlist{
		Header: USBIPControlHeader{
			Version:     USBIP_VERSION,
			CommandCode: USBIP_COMMAND_OP_REP_DEVLIST,
			Status:      0,
		},
		NumDevices: 1,
		Devices: []USBDeviceSummary{
			device.usbipSummary(),
		},
	}
}

type USBIPOpRepImport struct {
	header USBIPControlHeader
	device USBDeviceSummary
}

func opRepImport(writer io.Writer) USBIPOpRepImport {
	device := USBDevice{}
	return USBIPOpRepImport{
		header: USBIPControlHeader{
			Version:     USBIP_VERSION,
			CommandCode: USBIP_COMMAND_OP_REP_IMPORT,
			Status:      0,
		},
		device: device.usbipSummary(),
	}
}

type USBIPMessageHeader struct {
	Command        uint32
	SequenceNumber uint32
	DeviceId       uint32
	Direction      uint32
	Endpoint       uint32
}

func (header *USBIPMessageHeader) String() string {
	return fmt.Sprintf(
		"USBIPMessageHeader{ command: %04x, sequenceNumber: %04x, deviceId: %04x, direction %04x, endpoint %04x }",
		header.Command,
		header.SequenceNumber,
		header.DeviceId,
		header.Direction,
		header.Endpoint)
}

type USBIPCommandSubmit struct {
	Header               USBIPMessageHeader
	TransferFlags        uint32
	TransferBufferLength uint32
	StartFrame           uint32
	NumberOfPackets      uint32
	Interval             uint32
	Setup                uint64
}

func (command *USBIPCommandSubmit) String() string {
	return fmt.Sprintf("USBIPCommandSubmit{ "+
		"header: %v, "+
		"transferFlags: %04x, "+
		"transferBufferLength: %04x, "+
		"startFrame: %04x, "+
		"numberOfPackets: %04x, "+
		"interval: %04x"+
		"setup: %04x }",
		command.Header,
		command.TransferFlags,
		command.TransferBufferLength,
		command.StartFrame,
		command.NumberOfPackets,
		command.Interval,
		command.Setup)
}

func readUSBIPCommandSubmit(reader io.Reader) (USBIPCommandSubmit, error) {
	command := USBIPCommandSubmit{}
	err := binary.Read(reader, binary.BigEndian, &command)
	return command, err
}

type USBDevice struct {
	Index int
}

type USBDeviceSummary struct {
	Header          USBDeviceSummaryHeader
	DeviceInterface USBDeviceInterface // We only support one interface to use binary.Write/Read
}

type USBDeviceSummaryHeader struct {
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

type USBDeviceInterface struct {
	BInterfaceClass    uint8
	BInterfaceSubclass uint8
	Padding            uint8
}

func (device *USBDevice) usbipSummary() USBDeviceSummary {
	return USBDeviceSummary{
		Header:          device.usbipSummaryHeader(),
		DeviceInterface: device.usbipInterfacesSummary(),
	}
}

func (device *USBDevice) usbipSummaryHeader() USBDeviceSummaryHeader {
	path := [256]byte{}
	copy(path[:], []byte("/device/"+fmt.Sprint(device.Index)))
	busId := [32]byte{}
	copy(busId[:], []byte("1-1"))
	return USBDeviceSummaryHeader{
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

func (device *USBDevice) usbipInterfacesSummary() USBDeviceInterface {
	return USBDeviceInterface{
		BInterfaceClass:    3,
		BInterfaceSubclass: 0,
		Padding:            0,
	}
}
