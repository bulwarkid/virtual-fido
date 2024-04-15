package usbip

import (
	"bytes"
	"net"
	"strings"
	"sync"
	"syscall"

	"github.com/bulwarkid/virtual-fido/usb"
	"github.com/bulwarkid/virtual-fido/util"
)

var usbipLogger = util.NewLogger("[USBIP] ", util.LogLevelTrace)

type USBIPServer struct {
	device usb.USBDevice
}

func NewUSBIPServer(device usb.USBDevice) *USBIPServer {
	server := new(USBIPServer)
	server.device = device
	return server
}

func (server *USBIPServer) Start() {
	usbipLogger.Println("Starting USBIP server...")
	listener, err := net.Listen("tcp", ":3240")
	util.CheckErr(err, "Could not create listener")
	for {
		connection, err := listener.Accept()
		util.CheckErr(err, "Connection accept error")
		if !strings.HasPrefix(connection.RemoteAddr().String(), "127.0.0.1") {
			usbipLogger.Printf("Connection attempted from non-local address: %s", connection.RemoteAddr().String())
			connection.Close()
			continue
		}
		usbipConn := newUSBIPConnection(server, connection)
		usbipConn.handle()
	}
}

type usbipConnection struct {
	responseMutex *sync.Mutex
	conn          net.Conn
	server        *USBIPServer
}

func newUSBIPConnection(server *USBIPServer, conn net.Conn) *usbipConnection {
	usbipConn := new(usbipConnection)
	usbipConn.responseMutex = &sync.Mutex{}
	usbipConn.conn = conn
	usbipConn.server = server
	return usbipConn
}

func (conn *usbipConnection) handle() {
	for {
		header := util.ReadBE[USBIPControlHeader](conn.conn)
		usbipLogger.Printf("[CONTROL MESSAGE] %#v\n\n", header)
		if header.CommandCode == USBIP_COMMAND_OP_REQ_DEVLIST {
			reply := newOpRepDevlist()
			usbipLogger.Printf("[OP_REP_DEVLIST] %#v\n\n", reply)
			conn.writeResponse(util.ToBE(reply))
		} else if header.CommandCode == USBIP_COMMAND_OP_REQ_IMPORT {
			busID := util.Read(conn.conn, 32)
			util.Assert(bytes.Equal(busID, []byte("2-2")), "Invalid Bus ID Provided")
			reply := newOpRepImport()
			usbipLogger.Printf("[OP_REP_IMPORT] %s\n\n", reply)
			conn.writeResponse(util.ToBE(reply))
			for {
				conn.handleCommand()
			}
		} else {
			usbipLogger.Printf("Unknown Command Code: %d", header.CommandCode)
		}
	}
}

func (conn *usbipConnection) handleCommand() {
	util.Try(func() {
		header := util.ReadBE[USBIPMessageHeader](conn.conn)
		usbipLogger.Printf("[MESSAGE HEADER] %s\n\n", header)
		if header.Command == USBIP_CMD_SUBMIT {
			conn.handleCommandSubmit(header)
		} else if header.Command == USBIP_CMD_UNLINK {
			conn.handleCommandUnlink(header)
		} else {
			usbipLogger.Printf("Unsupported Command: %#v", header)
		}
	}, func(err interface{}) {
		usbipLogger.Printf("%#v", err)
	})
}

func (conn *usbipConnection) handleCommandSubmit(header USBIPMessageHeader) {
	command := util.ReadBE[USBIPCommandSubmitBody](conn.conn)
	setup := command.Setup()
	usbipLogger.Printf("[COMMAND SUBMIT] %s\n\n", command)
	transferBuffer := make([]byte, command.TransferBufferLength)
	if header.Direction == USBIP_DIR_OUT && command.TransferBufferLength > 0 {
		_, err := conn.conn.Read(transferBuffer)
		util.CheckErr(err, "Could not read transfer buffer")
	}
	// Getting the reponse may not be immediate, so we need a callback
	onReturnSubmit := func() {
		replyHeader := header.replyHeader()
		replyBody := USBIPReturnSubmitBody{
			Status:          0,
			ActualLength:    uint32(len(transferBuffer)),
			StartFrame:      0,
			NumberOfPackets: 0xFFFFFFFF, // This is a single packet transfer
			ErrorCount:      0,
			Padding:         0,
		}
		usbipLogger.Printf("[RETURN SUBMIT] %v %#v\n\n", replyHeader, replyBody)
		reply := util.Flatten([][]byte{util.ToBE(replyHeader), util.ToBE(replyBody)})
		if header.Direction == USBIP_DIR_IN {
			reply = append(reply, transferBuffer...)
		}
		conn.writeResponse(reply)
	}
	conn.server.device.HandleMessage(header.SequenceNumber, onReturnSubmit, header.Endpoint, setup, transferBuffer)
}

func (conn *usbipConnection) handleCommandUnlink(header USBIPMessageHeader) {
	unlink := util.ReadBE[USBIPCommandUnlinkBody](conn.conn)
	usbipLogger.Printf("[COMMAND UNLINK] %#v\n\n", unlink)
	var status int32
	if conn.server.device.RemoveWaitingRequest(unlink.UnlinkSequenceNumber) {
		status = -int32(syscall.ECONNRESET)
	} else {
		status = -int32(syscall.ENOENT)
	}
	replyHeader := header.replyHeader()
	replyBody := USBIPReturnUnlinkBody{
		Status:  status,
		Padding: [24]byte{},
	}
	reply := util.Flatten([][]byte{
		util.ToBE(replyHeader),
		util.ToBE(replyBody),
	})
	conn.writeResponse(reply)
}

func (conn *usbipConnection) writeResponse(data []byte) {
	conn.responseMutex.Lock()
	util.Write(conn.conn, data)
	conn.responseMutex.Unlock()
}
