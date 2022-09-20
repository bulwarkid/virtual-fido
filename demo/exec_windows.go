package demo

// Execute USB IP attach for Windows
func platformUsbIPExec() *exec.Cmd {
	return exec.Command("./usbip/usbip.exe", "attach", "-r", "127.0.0.1", "-b", "2-2")
}
