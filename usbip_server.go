package main

import (
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

func (server *USBIPServer) handleConnection(conn *net.Conn) {
	for {
		header := readBE[USBIPControlHeader](*conn)
		fmt.Printf("USBIP CONTROL MESSAGE: %#v\n\n", header)
		if header.CommandCode == USBIP_COMMAND_OP_REQ_DEVLIST {
			reply := newOpRepDevlist(server.device)
			fmt.Printf("OP_REP_DEVLIST: %#v\n\n", reply)
			write(*conn, toBE(reply))
		} else if header.CommandCode == USBIP_COMMAND_OP_REQ_IMPORT {
			busId := make([]byte, 32)
			bytesRead, err := (*conn).Read(busId)
			if bytesRead != 32 {
				panic(fmt.Sprintf("Could not read busId for OP_REQ_IMPORT: %v", err))
			}
			fmt.Println("BUS_ID: ", string(busId))
			reply := newOpRepImport(server.device)
			fmt.Printf("OP_REP_IMPORT: %s\n\n", reply)
			write(*conn, toBE(reply))
			server.handleCommands(conn)
		}
	}
}

func (server *USBIPServer) handleCommands(conn *net.Conn) {
	for {
		header := readBE[USBIPMessageHeader](*conn)
		fmt.Printf("--------------------------------------------\n")
		fmt.Printf("MESSAGE HEADER: %s - Direction: %s - Endpoint: %d\n\n", header.CommandName(), header.DirectionName(), header.Endpoint)
		if header.Command == USBIP_COMMAND_SUBMIT {
			server.handleCommandSubmit(conn, header)
		} else if header.Command == USBIP_COMMAND_UNLINK {
			server.handleCommandUnlink(conn, header)
			return
		} else {
			panic(fmt.Sprintf("Unsupported Command; %#v", header))
		}
	}
}

func (server *USBIPServer) handleCommandSubmit(conn *net.Conn, header USBIPMessageHeader) {
	command := readBE[USBIPCommandSubmitBody](*conn)
	setup := command.Setup()
	fmt.Printf("COMMAND SUBMIT: %s\n\n", setup)
	transferBuffer := make([]byte, command.TransferBufferLength)
	if header.Direction == USBIP_DIR_OUT && command.TransferBufferLength > 0 {
		_, err := (*conn).Read(transferBuffer)
		checkErr(err, "Could not read transfer buffer")
	}
	server.device.handleMessage(setup, transferBuffer)
	replyHeader, replyBody := newReturnSubmit(header, command, transferBuffer)
	fmt.Printf("RETURN SUBMIT: %v %#v\n\n", replyHeader, replyBody)
	write(*conn, toBE(replyHeader))
	write(*conn, toBE(replyBody))
	if header.Direction == USBIP_DIR_IN {
		write(*conn, transferBuffer)
	}
}

func (server *USBIPServer) handleCommandUnlink(conn *net.Conn, header USBIPMessageHeader) {
	unlink := readBE[USBIPCommandUnlinkBody](*conn)
	fmt.Printf("COMMAND UNLINK: %#v\n\n", unlink)
	replyHeader, replyBody := newReturnUnlink(header)
	write(*conn, toBE(replyHeader))
	write(*conn, toBE(replyBody))
}
