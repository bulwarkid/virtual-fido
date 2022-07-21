package main

func main() {
	ctapServer := NewCTAPHIDServer()
	device := NewFIDODevice(ctapServer)
	server := NewUSBIPServer(device)
	server.start()
}
