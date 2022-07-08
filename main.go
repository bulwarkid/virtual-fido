package main

import (
	"encoding/binary"
	"fmt"
	"net"
)

type USBIPHeader struct {
	Version     uint16
	CommandCode uint16
	Status      uint32
}

func handleConnection(conn *net.Conn) error {
	header := USBIPHeader{}
	err := binary.Read(*conn, binary.BigEndian, &header)
	if err != nil {
		return fmt.Errorf("Could not read USBIP header: %w", err)
	}
	fmt.Println(header)
	return nil
}

func main() {
	fmt.Println("Starting USBIP server...")
	listener, err := net.Listen("tcp", ":3240")
	if err != nil {
		fmt.Println("Could not create listener:", err)
		return
	}
	for {
		connection, err := listener.Accept()
		if err != nil {
			fmt.Println("Connection error:", err)
		}
		err = handleConnection(&connection)
		if err != nil {
			fmt.Println("Error processing connection:", err)
		}
	}
}
