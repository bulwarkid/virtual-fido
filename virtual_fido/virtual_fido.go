package virtual_fido

type VirtualFIDO struct{}

func (device *VirtualFIDO) Start() {
	client := newClient()
	ctapServer := newCTAPServer(*client)
	u2fServer := newU2FServer(*client)
	ctapHIDServer := newCTAPHIDServer(ctapServer, u2fServer)
	usbDevice := newUSBDevice(ctapHIDServer)
	server := newUSBIPServer(usbDevice)
	server.start()
}
