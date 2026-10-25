//go:build !windows

package transport

import "fmt"

// AttachUSBIPWin2 is unsupported on non-Windows platforms.
func AttachUSBIPWin2() error {
	return fmt.Errorf("usbip-win2 attach not supported on this platform")
}
