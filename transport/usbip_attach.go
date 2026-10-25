package transport

import "fmt"

// AttachUSBIP runs the external usbip attach command when available.
func AttachUSBIP() error {
	cmd := platformUSBIPExec()
	if cmd == nil {
		return fmt.Errorf("usbip attach not supported on this platform")
	}
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("usbip attach error: %w", err)
	}
	return nil
}
