package transport

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	virtual_fido "github.com/bulwarkid/virtual-fido"
)

// Prompt asks the user on stdin with default yes on empty.
func Prompt(prompt string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s ", prompt)
	response, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Could not read user input: %s - %s\n", response, err)
		return false
	}
	response = strings.ToLower(strings.TrimSpace(response))
	return response == "" || response == "y" || response == "yes"
}

func PromptString(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s ", prompt)
	response, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Could not read user input: %s - %s\n", response, err)
		return ""
	}
	return strings.TrimSpace(response)
}

// Mode chooses which transport to use.
type Mode string

const (
	ModeUSBIP     Mode = "usbip"
	ModeUHID      Mode = "uhid"
	ModeUSBIPWin2 Mode = "usbip-win2"
	ModeDarwin    Mode = "darwin"
)

// Start runs the virtual-fido server over the selected transport.
// On Linux defaults to UHID, elsewhere to USBIP, unless overridden by caller.
func Start(mode Mode, client virtual_fido.FIDOClient,
	deviceName string) {
	switch mode {
	case ModeUSBIP:
		runUsbipServer(client)
	case ModeUHID:
		runUhidServer(client, deviceName)
	case ModeUSBIPWin2:
		runUsbipWin2(client)
	case ModeDarwin:
		runDarwinServer(client, deviceName)
	default:
		fmt.Printf("unknown transport %q, falling back to usbip\n", mode)
		runUsbipServer(client)
	}
}

// TransportOptions returns the default transport and the help string of valid options.
func TransportOptions() (Mode, string) {
	switch runtime.GOOS {
	case "linux":
		return ModeUHID, "uhid or usbip"
	case "windows":
		return ModeUSBIPWin2, "usbip-win2 or usbip"
	case "darwin":
		return ModeDarwin, "darwin"
	default:
		return ModeUSBIP, "usbip"
	}
}

func runUsbipServer(client virtual_fido.FIDOClient) {
	wg := &sync.WaitGroup{}
	wg.Add(2)
	go func() {
		virtual_fido.Start(client)
		wg.Done()
	}()
	go func() {
		time.Sleep(500 * time.Millisecond)
		prog := platformUSBIPExec()
		if prog != nil {
			prog.Stdin = os.Stdin
			prog.Stdout = os.Stdout
			prog.Stderr = os.Stderr
			if err := prog.Run(); err != nil {
				fmt.Printf("usbip attach error: %v\n", err)
			}
		} else {
			fmt.Println("usbip attach not supported on this platform")
		}
		wg.Done()
	}()
	wg.Wait()
}

func runUhidServer(client virtual_fido.FIDOClient, deviceName string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		cancel()
	}()

	if err := virtual_fido.StartUHID(ctx, client, deviceName); err != nil {
		fmt.Printf("UHID error: %v\n", err)
	}
}

func Stop(mode Mode) {
	switch mode {
	case ModeDarwin:
		platformStopDarwin()
	default:
		// Other transports might not support soft stop yet or rely on SIGINT
	}
}
