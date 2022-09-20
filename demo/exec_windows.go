//go:build windows

package demo

// Execute USB IP attach for Windows
func platformUSBIPExec() *exec.Cmd {
	return exec.Command("./usbip/usbip.exe", "attach", "-r", "127.0.0.1", "-b", "2-2")
}
