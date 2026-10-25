//go:build windows

package transport

import (
	"fmt"

	"github.com/bulwarkid/virtual-fido/transport/usbipwin2"
)

// AttachUSBIPWin2 attaches the local usbip server using the usbip-win2 driver.
func AttachUSBIPWin2() error {
	c := usbipwin2.New("127.0.0.1:3240")
	if _, err := c.Attach(); err != nil {
		return fmt.Errorf("usbip-win2 attach error: %w", err)
	}
	return nil
}
