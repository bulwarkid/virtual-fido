//go:build !darwin || !cgo

package dkit

// Stub for dkit package when CGO is disabled or not on Darwin

import (
	"github.com/bulwarkid/virtual-fido/ctap_hid"
)

func Start(server *ctap_hid.CTAPHIDServer) {}
func Stop() {}
