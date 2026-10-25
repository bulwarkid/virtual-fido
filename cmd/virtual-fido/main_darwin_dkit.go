//go:build darwin && !hidvirtual && cgo

package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/bulwarkid/virtual-fido/cmd/virtual-fido/internal/airgap"
	"github.com/bulwarkid/virtual-fido/ctap_hid"
	"github.com/bulwarkid/virtual-fido/transport/dkit"
)

func runOnlineDarwin() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	go func() {
		<-sig
		cancel()
	}()

	fmt.Printf("Online-only Darwin relay (DKIT) started. Copy request hex to offline-only and paste responses back.\n")
	reader := bufio.NewReader(os.Stdin)

	ctapProxy := &offlineProxy{kind: airgap.HIDKindCTAP, reader: reader}
	u2fProxy := &offlineProxy{kind: airgap.HIDKindU2F, reader: reader}
	hidServer := ctap_hid.NewCTAPHIDServer(ctapProxy, u2fProxy)

	dkit.Start(hidServer)

	<-ctx.Done()
	dkit.Stop()
	return nil
}
