//go:build darwin && !hidvirtual && cgo

package transport

import (
	"context"
	"os"
	"os/signal"

	virtual_fido "github.com/bulwarkid/virtual-fido"
	"github.com/bulwarkid/virtual-fido/ctap"
	"github.com/bulwarkid/virtual-fido/ctap_hid"
	"github.com/bulwarkid/virtual-fido/transport/dkit"
	"github.com/bulwarkid/virtual-fido/u2f"
)

func runDarwinServer(client virtual_fido.FIDOClient, deviceName string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt)
		<-sig
		cancel()
	}()

	ctapServer := ctap.NewCTAPServer(client)
	u2fServer := u2f.NewU2FServer(client)
	ctapHIDServer := ctap_hid.NewCTAPHIDServer(ctapServer, u2fServer)

	go dkit.Start(ctapHIDServer)

	<-ctx.Done()
	dkit.Stop()
}
