//go:build linux

package main

import "os/exec"

// Execute USB IP attach for Linux
func platformUSBIPExec() *exec.Cmd {
	return exec.Command("sudo", "usbip", "attach", "-r", "127.0.0.1", "-b", "2-2")
}
