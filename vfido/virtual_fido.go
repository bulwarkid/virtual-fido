package vfido

func Start(client Client) {
	ctapServer := newCTAPServer(client)
	u2fServer := newU2FServer(client)
	ctapHIDServer := newCTAPHIDServer(ctapServer, u2fServer)
	usbDevice := newUSBDevice(ctapHIDServer)
	server := newUSBIPServer(usbDevice)
	server.start()
}
