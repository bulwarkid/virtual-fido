package virtual_fido

import (
	"io"

	"github.com/bulwarkid/virtual-fido/ctap"
	"github.com/bulwarkid/virtual-fido/u2f"
	"github.com/bulwarkid/virtual-fido/util"
)

type FIDOClient interface {
	u2f.U2FClient
	ctap.CTAPClient
}

func Start(client FIDOClient) {
	// Calls either the Mac or USB/IP client, based on system
	startClient(client)
}

func SetLogLevel(level util.LogLevel) {
	util.SetLogLevel(level)
}

func SetLogOutput(out io.Writer) {
	util.SetLogOutput(out)
}
