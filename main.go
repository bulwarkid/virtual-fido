package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

func handleCommands(conn *net.Conn) error {
	for {
		command, err := readUSBIPCommandSubmit(*conn)
		if err != nil {
			return fmt.Errorf("Could not read USBIP command: %w", err)
		}
		fmt.Printf("%#v\n", command)
	}
}

func handleConnection(conn *net.Conn) error {
	for {
		header, err := readUSBIPHeader(*conn)
		if err != nil {
			return fmt.Errorf("Could not read USBIP header: %w", err)
		}
		fmt.Printf("Received USBIP control message: %#v\n", header)
		response := new(bytes.Buffer)
		if header.CommandCode == USBIP_COMMAND_OP_REQ_DEVLIST {
			reply := opRepDevlist()
			fmt.Printf("Writing OP_REP_DEVLIST: %#v\n", reply)
			err = binary.Write(*conn, binary.BigEndian, reply)
			if err != nil {
				return fmt.Errorf("Could not write OP_REP_DEVLIST: %w", err)
			}
		} else if header.CommandCode == USBIP_COMMAND_OP_REQ_IMPORT {
			busId := make([]byte, 32)
			bytesRead, err := (*conn).Read(busId)
			if err != nil || bytesRead != 32 {
				return fmt.Errorf("Could not read busId for OP_REQ_IMPORT: %w", err)
			}
			fmt.Println("Bus ID: ", busId)
			reply := opRepImport(response)
			fmt.Printf("Writing OP_REP_IMPORT: %#v\n", reply)
			err = binary.Write(*conn, binary.BigEndian, reply)
			if err != nil {
				return fmt.Errorf("Could not write OP_REP_IMPORT: %w", err)
			}
			handleCommands(conn)
		}
	}
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
