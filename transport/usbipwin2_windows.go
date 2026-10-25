//go:build windows

package transport

import (
	"fmt"
	"time"

	virtual_fido "github.com/bulwarkid/virtual-fido"
	"github.com/bulwarkid/virtual-fido/transport/usbipwin2"
)

// runUsbipWin2 starts the local usbip server and attaches using the usbip-win2 driver.
func runUsbipWin2(client virtual_fido.FIDOClient) {
	go virtual_fido.Start(client)
	// Give the server a moment to start listening.
	time.Sleep(500 * time.Millisecond)

	c := usbipwin2.New("127.0.0.1:3240")
	if _, err := c.Attach(); err != nil {
		fmt.Printf("usbip-win2 attach error: %v\n", err)
	}
}
