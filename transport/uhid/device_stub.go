//go:build !linux

package uhid

import (
	"context"
	"errors"
)

// Device is unsupported on non-Linux platforms.
type Device struct{}

func Open(name string, reportDescriptor []byte) (*Device, error) {
	return nil, errors.New("uhid only available on linux")
}

func (d *Device) Close() error                                  { return nil }
func (d *Device) ReadReport(_ context.Context) ([]byte, error)  { return nil, errors.New("unsupported") }
func (d *Device) WriteReport(_ context.Context, _ []byte) error { return errors.New("unsupported") }
func (d *Device) WaitReady()                                    {}
