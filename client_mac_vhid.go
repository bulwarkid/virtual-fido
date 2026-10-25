//go:build darwin && hidvirtual

package virtual_fido

import (
	"github.com/bulwarkid/virtual-fido/ctap"
	"github.com/bulwarkid/virtual-fido/ctap_hid"
	"github.com/bulwarkid/virtual-fido/transport/vhid"
	"github.com/bulwarkid/virtual-fido/u2f"
)

/*
 * Mac client using Virtual HID (CoreHID).
 */
func startClient(client FIDOClient) {
	ctapServer := ctap.NewCTAPServer(client)
	u2fServer := u2f.NewU2FServer(client)
	ctapHIDServer := ctap_hid.NewCTAPHIDServer(ctapServer, u2fServer)
	vhid.Start(ctapHIDServer)
}
