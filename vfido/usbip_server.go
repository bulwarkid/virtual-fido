package vfido

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
)

var usbipLogger = newLogger("[USBIP] ", false)

type USBIPServer struct {
	device        USBDevice
	responseMutex *sync.Mutex
}

func newUSBIPServer(device USBDevice) *USBIPServer {
	server := new(USBIPServer)
	server.device = device
	server.responseMutex = &sync.Mutex{}
	return server
}

func (server *USBIPServer) start() {
	usbipLogger.Println("Starting USBIP server...")
	listener, err := net.Listen("tcp", ":3240")
	checkErr(err, "Could not create listener")
	for {
		connection, err := listener.Accept()
		checkErr(err, "Connection accept error")
		if !strings.HasPrefix(connection.RemoteAddr().String(), "127.0.0.1") {
			usbipLogger.Printf("Connection attempted from non-local address: %s", connection.RemoteAddr().String())
			connection.Close()
			continue
		}
		server.handleConnection(&connection)
	}
}

func (server *USBIPServer) handleConnection(conn *net.Conn) {
	for {
		header := readBE[USBIPControlHeader](*conn)
		usbipLogger.Printf("[CONTROL MESSAGE] %#v\n\n", header)
		if header.CommandCode == USBIP_COMMAND_OP_REQ_DEVLIST {
			reply := newOpRepDevlist(server.device)
			usbipLogger.Printf("[OP_REP_DEVLIST] %#v\n\n", reply)
			write(*conn, toBE(reply))
		} else if header.CommandCode == USBIP_COMMAND_OP_REQ_IMPORT {
			busId := make([]byte, 32)
			bytesRead, err := (*conn).Read(busId)
			if bytesRead != 32 {
				panic(fmt.Sprintf("Could not read busId for OP_REQ_IMPORT: %v", err))
			}
			reply := newOpRepImport(server.device)
			usbipLogger.Printf("[OP_REP_IMPORT] %s\n\n", reply)
			write(*conn, toBE(reply))
			server.handleCommands(conn)
		}
	}
}

func (server *USBIPServer) handleCommands(conn *net.Conn) {
	for {
		// fmt.Printf("--------------------------------------------\n\n")
		header := readBE[USBIPMessageHeader](*conn)
		usbipLogger.Printf("[MESSAGE HEADER] %s\n\n", header)
		if header.Command == USBIP_COMMAND_SUBMIT {
			server.handleCommandSubmit(conn, header)
		} else if header.Command == USBIP_COMMAND_UNLINK {
			server.handleCommandUnlink(conn, header)
		} else {
			panic(fmt.Sprintf("Unsupported Command; %#v", header))
		}
	}
}

func (server *USBIPServer) handleCommandSubmit(conn *net.Conn, header USBIPMessageHeader) {
	command := readBE[USBIPCommandSubmitBody](*conn)
	setup := command.Setup()
	usbipLogger.Printf("[COMMAND SUBMIT] %s\n\n", command)
	transferBuffer := make([]byte, command.TransferBufferLength)
	if header.Direction == USBIP_DIR_OUT && command.TransferBufferLength > 0 {
		_, err := (*conn).Read(transferBuffer)
		checkErr(err, "Could not read transfer buffer")
	}
	// Getting the reponse may not be immediate, so we need a callback
	onReturnSubmit := func() {
		server.responseMutex.Lock()
		replyHeader := USBIPMessageHeader{
			Command:        USBIP_COMMAND_RET_SUBMIT,
			SequenceNumber: header.SequenceNumber,
			DeviceId:       header.DeviceId,
			Direction:      USBIP_DIR_OUT,
			Endpoint:       header.Endpoint,
		}
		replyBody := USBIPReturnSubmitBody{
			Status:          0,
			ActualLength:    uint32(len(transferBuffer)),
			StartFrame:      0,
			NumberOfPackets: 0,
			ErrorCount:      0,
			Padding:         0,
		}
		usbipLogger.Printf("[RETURN SUBMIT] %v %#v\n\n", replyHeader, replyBody)
		write(*conn, toBE(replyHeader))
		write(*conn, toBE(replyBody))
		if header.Direction == USBIP_DIR_IN {
			write(*conn, transferBuffer)
		}
		server.responseMutex.Unlock()
	}
	server.device.handleMessage(header.SequenceNumber, onReturnSubmit, header.Endpoint, setup, transferBuffer)
}

func (server *USBIPServer) handleCommandUnlink(conn *net.Conn, header USBIPMessageHeader) {
	unlink := readBE[USBIPCommandUnlinkBody](*conn)
	usbipLogger.Printf("[COMMAND UNLINK] %#v\n\n", unlink)
	var status int32
	if server.device.removeWaitingRequest(unlink.UnlinkSequenceNumber) {
		status = -int32(syscall.ECONNRESET)
	} else {
		status = -int32(syscall.ENOENT)
	}
	replyHeader := USBIPMessageHeader{
		Command:        USBIP_COMMAND_RET_UNLINK,
		SequenceNumber: header.SequenceNumber,
		DeviceId:       header.DeviceId,
		Direction:      USBIP_DIR_OUT,
		Endpoint:       header.Endpoint,
	}
	replyBody := USBIPReturnUnlinkBody{
		Status:  status,
		Padding: [24]byte{},
	}
	write(*conn, toBE(replyHeader))
	write(*conn, toBE(replyBody))
}
