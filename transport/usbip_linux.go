//go:build linux

package transport

import "os/exec"

func platformUSBIPExec() *exec.Cmd {
	return exec.Command("sudo", "usbip", "attach", "-r", "127.0.0.1", "-b", "2-2")
}
