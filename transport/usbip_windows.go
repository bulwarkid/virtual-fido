//go:build windows

package transport

import "os/exec"

func platformUSBIPExec() *exec.Cmd {
	cmd := exec.Command(".\\usbip.exe", "attach", "-r", "127.0.0.1", "-b", "2-2")
	cmd.Dir = ".\\cmd\\demo\\usbip\\bin"
	return cmd
}
