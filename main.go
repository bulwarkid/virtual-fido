package main

import (
	"fmt"
	"net"
)

var device FIDODevice

func handleCommandSubmit(conn *net.Conn, header USBIPMessageHeader, command USBIPCommandSubmitBody) error {
	checkEOF(conn)
	transferBuffer := make([]byte, command.TransferBufferLength)
	if header.Direction == USBIP_DIR_OUT && command.TransferBufferLength > 0 {
		_, err := (*conn).Read(transferBuffer)
		if err != nil {
			return fmt.Errorf("Could not read transfer buffer: %w", err)
		}
	}
	switch command.Setup.BRequest {
	case USB_REQUEST_GET_DESCRIPTOR:
		checkEOF(conn)
		descriptor, err := device.getDescriptor(command.Setup.WValue)
		if err != nil {
			return fmt.Errorf("Could not get descriptor: %#v %w", command, err)
		}
		copy(transferBuffer, descriptor)
		replyHeader, replyBody, _ := newReturnSubmit(header, command, (transferBuffer))
		fmt.Printf("RETURN SUBMIT: %#v %#v %v %v %v\n\n", replyHeader, replyBody, toBE(replyHeader), toBE(replyBody), transferBuffer)
		err = write(*conn, toBE(replyHeader))
		if err != nil {
			return fmt.Errorf("Could not write device descriptor header: %w", err)
		}
		err = write(*conn, toBE(replyBody))
		if err != nil {
			return fmt.Errorf("Could not write device descriptor message body: %w", err)
		}
		err = write(*conn, transferBuffer)
		if err != nil {
			return fmt.Errorf("Could not write device descriptor: %w", err)
		}
		checkEOF(conn)
	default:
		return fmt.Errorf("Invalid CMD_SUBMIT bRequest: %d", command.Setup.BRequest)
	}
	return nil
}

func handleCommands(conn *net.Conn) error {
	for {
		checkEOF(conn)
		header, err := readBE[USBIPMessageHeader](*conn)
		if err != nil {
			return fmt.Errorf("Could not read USBIP message header: %w", err)
		}
		fmt.Printf("MESSAGE HEADER: %#v\n\n", header)
		checkEOF(conn)
		if header.Command == USBIP_COMMAND_SUBMIT {
			command, err := readBE[USBIPCommandSubmitBody](*conn)
			if err != nil {
				return fmt.Errorf("Could not read CMD_SUBMIT body: %w", err)
			}
			fmt.Printf("COMMAND SUBMIT: %#v\n\n", command)
			err = handleCommandSubmit(conn, header, command)
			if err != nil {
				return fmt.Errorf("Could not handle CMD_SUBMIT: %w", err)
			}
		} else if header.Command == USBIP_COMMAND_UNLINK {
			unlink, err := readBE[USBIPCommandUnlinkBody](*conn)
			if err != nil {
				return fmt.Errorf("Could not read CMD_UNLINK body: %w", err)
			}
			fmt.Printf("COMMAND UNLINK: %#v\n\n", unlink)
		} else {
			return fmt.Errorf("Unsupported Command: %#v", header)
		}
	}
}

func handleConnection(conn *net.Conn) error {
	for {
		header, err := readBE[USBIPControlHeader](*conn)
		if err != nil {
			return fmt.Errorf("Could not read USBIP header: %w", err)
		}
		fmt.Printf("Received USBIP control message: %#v\n\n", header)
		checkEOF(conn)
		if header.CommandCode == USBIP_COMMAND_OP_REQ_DEVLIST {
			reply := newOpRepDevlist()
			fmt.Printf("Writing OP_REP_DEVLIST: %#v\n\n", reply)
			err = write(*conn, toBE(reply))
			if err != nil {
				return fmt.Errorf("Could not write OP_REP_DEVLIST: %w", err)
			}
		} else if header.CommandCode == USBIP_COMMAND_OP_REQ_IMPORT {
			busId := make([]byte, 32)
			bytesRead, err := (*conn).Read(busId)
			if err != nil || bytesRead != 32 {
				return fmt.Errorf("Could not read busId for OP_REQ_IMPORT: %w", err)
			}
			fmt.Println("BUS_ID: ", string(busId))
			reply := newOpRepImport()
			fmt.Printf("Writing OP_REP_IMPORT: %#v\n\n", reply)
			err = write(*conn, toBE(reply))
			if err != nil {
				return fmt.Errorf("Could not write OP_REP_IMPORT: %w", err)
			}
			err = handleCommands(conn)
			if err != nil {
				return fmt.Errorf("Could not handle commands: %w", err)
			}
		}
	}
}

func main() {
	fmt.Println("Starting USBIP server...")
	device = FIDODevice{}
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
