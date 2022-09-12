package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
	"virtual_fido"
)

func prompt(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println(prompt)
	fmt.Print("--> ")
	response, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Could not read user input: %s - %s\n", response, err)
		panic(err)
	}
	return response
}

type ClientSupport struct{}

func (support *ClientSupport) ApproveAccountCreation(relyingParty string) bool {
	response := prompt(fmt.Sprintf("Approve account creation for \"%s\" (Y/n)?", relyingParty))
	response = strings.ToLower(strings.TrimSpace(response))
	if response == "y" || response == "yes" {
		return true
	}
	return false
}

func (support *ClientSupport) ApproveLogin(relyingParty string, username string) bool {
	response := prompt(fmt.Sprintf("Approve login for \"%s\" with identity \"%s\" (Y/n)?", relyingParty, username))
	response = strings.ToLower(strings.TrimSpace(response))
	if response == "y" || response == "yes" {
		return true
	}
	return false
}

func (support *ClientSupport) SaveData(data []byte) {
	// TODO: Implement ability to set file name
	f, err := os.OpenFile(vaultFilename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	checkErr(err, "Could not open vault file")
	_, err = f.Write(data)
	checkErr(err, "Could not write vault data")
}

func (support *ClientSupport) RetrieveData() []byte {
	// TODO: Implement ability to set file name
	f, err := os.Open(vaultFilename)
	if os.IsNotExist(err) {
		return nil
	}
	checkErr(err, "Could not open vault")
	data, err := io.ReadAll(f)
	checkErr(err, "Could not read vault data")
	return data
}

func (support *ClientSupport) Passphrase() string {
	// TODO: Implement
	return "test passphrase"
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
		prog := exec.Command("./usbip/usbip.exe", "attach", "-r", "127.0.0.1", "-b", "2-2")
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
