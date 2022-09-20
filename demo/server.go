package demo

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"virtual_fido"
)

func prompt(prompt string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println(prompt)
	fmt.Print("--> ")
	response, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Could not read user input: %s - %s\n", response, err)
		panic(err)
	}
	response = strings.ToLower(strings.TrimSpace(response))
	if response == "y" || response == "yes" {
		return true
	}
	return false
}

type ClientSupport struct {
	vaultFilename   string
	vaultPassphrase string
}

func (support *ClientSupport) ApproveClientAction(action virtual_fido.ClientAction, params virtual_fido.ClientActionRequestParams) bool {
	switch action {
	case virtual_fido.CLIENT_ACTION_FIDO_GET_ASSERTION:
		return prompt(fmt.Sprintf("Approve login for \"%s\" with identity \"%s\" (Y/n)?", params.RelyingParty, params.UserName))
	case virtual_fido.CLIENT_ACTION_FIDO_MAKE_CREDENTIAL:
		return prompt(fmt.Sprintf("Approve account creation for \"%s\" (Y/n)?", params.RelyingParty))
	case virtual_fido.CLIENT_ACTION_U2F_AUTHENTICATE:
		return prompt("Approve registration of U2F device (Y/n)?")
	case virtual_fido.CLIENT_ACTION_U2F_REGISTER:
		return prompt("Approve use of U2F device (Y/n)?")
	}
	fmt.Printf("Unknown client action for approval: %d\n", action)
	return false
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

func runServer(client virtual_fido.Client) {
	wg := &sync.WaitGroup{}
	wg.Add(2)
	go func() {
		virtual_fido.Start(client)
		wg.Done()
	}()
	go func() {
		time.Sleep(500 * time.Millisecond)
		prog := platformUSBIPExec()
		prog.Stdin = os.Stdin
		prog.Stdout = os.Stdout
		prog.Stderr = os.Stderr
		err := prog.Run()
		if err != nil {
			fmt.Printf("Error: %s\n", err)
		}
		wg.Done()
	}()
	wg.Wait()
}
