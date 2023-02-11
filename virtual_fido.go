package virtual_fido

import (
	"io"

	"github.com/bulwarkid/virtual-fido/fido_client"
	"github.com/bulwarkid/virtual-fido/util"
)

func Start(client fido_client.FIDOClient) {
	// Calls either the Mac or USB/IP client, based on system
	startClient(client)
}

func SetLogLevel(level util.LogLevel) {
	util.SetLogLevel(level)
}

func SetLogOutput(out io.Writer) {
	util.SetLogOutput(out)
}
