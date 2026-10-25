//go:build darwin && cgo

package transport

import "github.com/bulwarkid/virtual-fido/transport/vhid"

func platformStopDarwin() {
	vhid.Stop()
}
