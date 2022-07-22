package main

func main() {
	ctapServer := CTAPServer{}
	ctapHIDServer := NewCTAPHIDServer(&ctapServer)
	device := NewUSBDevice(ctapHIDServer)
	server := NewUSBIPServer(device)
	server.start()
}
