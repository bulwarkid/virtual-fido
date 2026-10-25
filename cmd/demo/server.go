package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	virtual_fido "github.com/bulwarkid/virtual-fido"
	"github.com/bulwarkid/virtual-fido/fido_client"
	"github.com/bulwarkid/virtual-fido/transport"
)

func prompt(prompt string) bool { return transport.Prompt(prompt) }

type ClientSupport struct {
	vaultFilename   string
	vaultPassphrase string
}

func (support *ClientSupport) ApproveClientAction(action fido_client.ClientAction, params fido_client.ClientActionRequestParams) (bool, int) {
	switch action {
	case fido_client.ClientActionFIDOGetAssertion:
		return prompt(fmt.Sprintf("Approve login for \"%s\" with identity \"%s\" (Y/n)?", params.RelyingParty, params.UserName)), 0
	case fido_client.ClientActionFIDOMakeCredential:
		return prompt(fmt.Sprintf("Approve account creation for \"%s\" (Y/n)?", params.RelyingParty)), 0
	case fido_client.ClientActionU2FAuthenticate:
		return prompt("Approve registration of U2F device (Y/n)?"), 0
	case fido_client.ClientActionU2FRegister:
		return prompt("Approve use of U2F device (Y/n)?"), 0
	}
	fmt.Printf("Unknown client action for approval: %d\n", action)
	return false, 0
}

func (support *ClientSupport) SaveData(data []byte) {
	f, err := os.OpenFile(support.vaultFilename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	checkErr(err, "Could not open vault file")
	_, err = f.Write(data)
	checkErr(err, "Could not write vault data")
}

func (support *ClientSupport) RetrieveData() []byte {
	f, err := os.Open(support.vaultFilename)
	if os.IsNotExist(err) {
		return nil
	}
	checkErr(err, "Could not open vault")
	data, err := io.ReadAll(f)
	checkErr(err, "Could not read vault data")
	return data
}

func (support *ClientSupport) Passphrase() string {
	return support.vaultPassphrase
}

func runServer(client virtual_fido.FIDOClient) {
	switch strings.ToLower(transportMode) {
	case "usbip":
		transport.Start(transport.ModeUSBIP, client, "Virtual FIDO")
	case "uhid":
		transport.Start(transport.ModeUHID, client, "Virtual FIDO")
	case "usbip-win2":
		transport.Start(transport.ModeUSBIPWin2, client, "Virtual FIDO")
	default:
		_, options := transport.TransportOptions()
		fmt.Printf("Unknown transport %q; expected %s\n", transportMode, options)
	}
}
