package main

func main() {
	ctapServer := CTAPServer{}
	ctapHIDServer := NewCTAPHIDServer(&ctapServer)
	device := NewFIDODevice(ctapHIDServer)
	server := NewUSBIPServer(device)
	server.start()
}
