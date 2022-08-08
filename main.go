package main

func main() {
	client := NewClient()
	ctapServer := NewCTAPServer(client)
	u2fServer := NewU2FServer(client)
	ctapHIDServer := NewCTAPHIDServer(ctapServer, u2fServer)
	device := NewUSBDevice(ctapHIDServer)
	server := NewUSBIPServer(device)
	server.start()
}
