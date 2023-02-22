//go:build linux || windows

package virtual_fido

import (
	"github.com/bulwarkid/virtual-fido/ctap"
	"github.com/bulwarkid/virtual-fido/ctap_hid"
	"github.com/bulwarkid/virtual-fido/u2f"
	"github.com/bulwarkid/virtual-fido/usbip"
)

func startClient(client FIDOClient) {
	ctapServer := ctap.NewCTAPServer(client)
	u2fServer := u2f.NewU2FServer(client)
	ctapHIDServer := ctap_hid.NewCTAPHIDServer(ctapServer, u2fServer)
	usbDevice := usbip.NewUSBDevice(ctapHIDServer)
	server := usbip.NewUSBIPServer(usbDevice)
	server.Start()
}
