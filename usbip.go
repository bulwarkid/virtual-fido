package main

import (
	"encoding/binary"
	"fmt"
	"io"
)

type USBIPHeader struct {
	Version     uint16
	CommandCode uint16
	Status      uint32
}

func (header *USBIPHeader) String() string {
	return fmt.Sprintf("USBIPHeader{ Version: 0x%04x, Command: 0x%04x, Status: 0x%08x }", header.Version, header.CommandCode, header.Status)
}

func readUSBIPHeader(reader io.Reader) (*USBIPHeader, error) {
	header := USBIPHeader{}
	err := binary.Read(reader, binary.BigEndian, &header)
	if err != nil {
		return nil, fmt.Errorf("Could not read USBIP header: %w", err)
	}
	return &header, nil
}
