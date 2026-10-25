package transport

import "testing"

func TestModesDistinct(t *testing.T) {
	if ModeUSBIP == ModeUHID {
		t.Fatal("transport modes collide")
	}
}
