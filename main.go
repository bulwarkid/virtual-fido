package main

func main() {
	ctapServer := CTAPServer{}
	client := NewClient()
	u2fServer := NewU2FServer(client)
	ctapHIDServer := NewCTAPHIDServer(&ctapServer, u2fServer)
	device := NewUSBDevice(ctapHIDServer)
	server := NewUSBIPServer(device)
	server.start()
}
