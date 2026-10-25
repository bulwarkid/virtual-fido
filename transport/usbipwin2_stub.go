//go:build !windows

package transport

import virtual_fido "github.com/bulwarkid/virtual-fido"

// runUsbipWin2 is a no-op on non-Windows platforms.
func runUsbipWin2(_ virtual_fido.FIDOClient) {}
