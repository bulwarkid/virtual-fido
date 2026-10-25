//go:build !darwin || !cgo

package vhid

// Stub for vhid package when CGO is disabled or not on Darwin

import (
	"github.com/bulwarkid/virtual-fido/ctap_hid"
)

func Start(server *ctap_hid.CTAPHIDServer) {}
func Stop() {}
