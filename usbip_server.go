package main

import (
	"bytes"
	"fmt"
	"net"
)

type USBIPServer struct {
	device *FIDODevice
}

func NewUSBIPServer(device *FIDODevice) *USBIPServer {
	server := new(USBIPServer)
	server.device = device
	return server
}

func (server *USBIPServer) start() {
	fmt.Println("Starting USBIP server...")
	listener, err := net.Listen("tcp", ":3240")
	checkErr(err, "Could not create listener")
	for {
		connection, err := listener.Accept()
		checkErr(err, "Connection accept error")
		server.handleConnection(&connection)
	}
}

func (server *USBIPServer) handleCommands(conn *net.Conn) {
	for {
		header := readBE[USBIPMessageHeader](*conn)
		fmt.Printf("MESSAGE HEADER: %v\n\n", header)
		if header.Command == USBIP_COMMAND_SUBMIT {
			command := readBE[USBIPCommandSubmitBody](*conn)
			server.handleCommandSubmit(conn, header, command)
		} else if header.Command == USBIP_COMMAND_UNLINK {
			unlink := readBE[USBIPCommandUnlinkBody](*conn)
			fmt.Printf("COMMAND UNLINK: %#v\n\n", unlink)
			replyHeader, replyBody := newReturnUnlink(header)
			write(*conn, toBE(replyHeader))
			write(*conn, toLE(replyBody))
			return
		} else {
			panic(fmt.Sprintf("Unsupported Command; %#v", header))
		}
	}
}

func (server *USBIPServer) handleConnection(conn *net.Conn) {
	for {
		header := readBE[USBIPControlHeader](*conn)
		fmt.Printf("USBIP CONTROL MESSAGE: %#v\n\n", header)
		if header.CommandCode == USBIP_COMMAND_OP_REQ_DEVLIST {
			reply := newOpRepDevlist(&device)
			fmt.Printf("OP_REP_DEVLIST: %#v\n\n", reply)
			write(*conn, toBE(reply))
		} else if header.CommandCode == USBIP_COMMAND_OP_REQ_IMPORT {
			busId := make([]byte, 32)
			bytesRead, err := (*conn).Read(busId)
			if bytesRead != 32 {
				panic(fmt.Sprintf("Could not read busId for OP_REQ_IMPORT: %v", err))
			}
			fmt.Println("BUS_ID: ", string(busId))
			reply := newOpRepImport(&device)
			fmt.Printf("OP_REP_IMPORT: %s\n\n", reply)
			write(*conn, toBE(reply))
			server.handleCommands(conn)
		}
	}
}

func (server *USBIPServer) handleCommandSubmit(conn *net.Conn, header USBIPMessageHeader, command USBIPCommandSubmitBody) {
	setup := readLE[USBSetupPacket](bytes.NewBuffer(command.Setup[:]))
	fmt.Printf("COMMAND SUBMIT: %s\n\n", command)
	transferBuffer := make([]byte, command.TransferBufferLength)
	if header.Direction == USBIP_DIR_OUT && command.TransferBufferLength > 0 {
		_, err := (*conn).Read(transferBuffer)
		checkErr(err, "Could not read transfer buffer")
	}
	if setup.recipient() == USB_REQUEST_RECIPIENT_DEVICE {
		handleDeviceRequest(conn, setup, transferBuffer)
	} else if setup.recipient() == USB_REQUEST_RECIPIENT_INTERFACE {
		handleInterfaceRequest(conn, setup)
	} else {
		panic(fmt.Sprintf("Invalid CMD_SUBMIT recipient: %d", setup.recipient()))
	}
	replyHeader, replyBody := newReturnSubmit(header, command, (transferBuffer))
	fmt.Printf("RETURN SUBMIT: %v %#v\n\n", replyHeader, replyBody)
	write(*conn, toBE(replyHeader))
	write(*conn, toBE(replyBody))
	write(*conn, transferBuffer)
}
