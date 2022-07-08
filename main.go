package main

import (
	"fmt"
	"net"
)

func handleConnection(conn *net.Conn) error {
	header, err := readUSBIPHeader(*conn)
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
