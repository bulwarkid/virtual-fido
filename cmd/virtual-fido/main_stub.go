//go:build !darwin || !cgo

package main

import "errors"

func runOnlineDarwin() error {
	return errors.New("online-only darwin mode only available on macOS")
}
