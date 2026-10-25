//go:build darwin

package transport

import "os/exec"

func platformUSBIPExec() *exec.Cmd {
	return nil
}
