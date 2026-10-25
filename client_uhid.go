//go:build linux

package virtual_fido

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/bulwarkid/virtual-fido/ctap"
	"github.com/bulwarkid/virtual-fido/ctap_hid"
	"github.com/bulwarkid/virtual-fido/u2f"
	"github.com/bulwarkid/virtual-fido/transport/uhid"
)

// StartUHID runs the virtual authenticator over a Linux UHID device using pure Go (no usbip).
// It blocks until the context is canceled or an error occurs.
func StartUHID(ctx context.Context, client FIDOClient, name string) error {
	if name == "" {
		name = "Virtual FIDO"
	}
	dev, err := uhid.Open(name, uhid.ReportDescriptorFIDO)
	if err != nil {
		return err
	}
	defer dev.Close()
	go func() {
		<-ctx.Done()
		_ = dev.Close()
	}()
	dev.WaitReady()

	ctapServer := ctap.NewCTAPServer(client)
	u2fServer := u2f.NewU2FServer(client)
	hidServer := ctap_hid.NewCTAPHIDServer(ctapServer, u2fServer)
	hidServer.SetResponseHandler(func(resp []byte) {
		if ctx.Err() != nil {
			return
		}
		if err := dev.WriteReport(ctx, resp); err != nil {
			log.Printf("uhid write error: %v", err)
		}
	})

	log.Printf("UHID virtual authenticator started as %q. Press Ctrl+C to exit.", name)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		report, err := dev.ReadReport(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			// Give the loop a brief pause to avoid hot-looping on transient errors.
			time.Sleep(10 * time.Millisecond)
			return err
		}
		hidServer.HandleMessage(report)
	}
}
