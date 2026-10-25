//go:build !darwin || !cgo

package transport

func platformStopDarwin() {
	// No-op on non-Darwin platforms
}
