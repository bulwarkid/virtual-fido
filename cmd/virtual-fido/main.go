package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/bulwarkid/virtual-fido/cmd/virtual-fido/internal/airgap"
	"github.com/bulwarkid/virtual-fido/cmd/virtual-fido/internal/client"
	"github.com/bulwarkid/virtual-fido/cmd/virtual-fido/internal/seed"
	"github.com/bulwarkid/virtual-fido/cmd/virtual-fido/internal/state"
	"github.com/bulwarkid/virtual-fido/cose"
	"github.com/bulwarkid/virtual-fido/ctap"
	"github.com/bulwarkid/virtual-fido/ctap_hid"
	"github.com/bulwarkid/virtual-fido/fido_client"
	"github.com/bulwarkid/virtual-fido/transport"
	"github.com/bulwarkid/virtual-fido/transport/uhid"
	"github.com/bulwarkid/virtual-fido/u2f"
	"github.com/bulwarkid/virtual-fido/usb"
	"github.com/bulwarkid/virtual-fido/usbip"
	"github.com/bulwarkid/virtual-fido/util"
	"github.com/bulwarkid/virtual-fido/webauthn"
	"github.com/spf13/cobra"
)

func main() {
	root := &cobra.Command{
		Use:   "virtual-fido",
		Short: "Seed-based virtual FIDO toolchain",
	}

	root.AddCommand(genSeedCmd(), runCmd(), onlineOnlyCmd(), offlineOnlyCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func genSeedCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "gen-seed",
		Short: "Generate a new random seed (32 bytes, hex)",
		RunE: func(cmd *cobra.Command, args []string) error {
			buf := make([]byte, 32)
			if _, err := rand.Read(buf); err != nil {
				return fmt.Errorf("generate seed: %w", err)
			}
			fmt.Println(hex.EncodeToString(buf))
			return nil
		},
	}
}

func runCmd() *cobra.Command {
	var seedFile string
	var countersPath string
	var transportFlag string
	var deviceName string
	var alwaysApprove bool
	var autoSelect bool
	var signalFile string
	var deferredStart bool
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run virtual authenticator (seed-based)",
		RunE: func(cmd *cobra.Command, args []string) error {
			seedBytes, err := seed.Load(seedFile)
			if err != nil {
				return fmt.Errorf("load seed: %w", err)
			}
			var counters client.CounterState
			if countersPath == "" {
				fmt.Println("Using in-memory time-based counters")
				counters = state.NewTimeBasedCounterStore(0, nil)
			} else {
				store := state.NewStore(countersPath, seedBytes)
				cs, err := state.NewCounterStore(store)
				if err != nil {
					return fmt.Errorf("load counters: %w", err)
				}
				fmt.Println("Loaded counters:")
				fmt.Print(cs.String())
				counters = cs
			}
			approver := newPromptApprover(alwaysApprove, autoSelect, signalFile, true)
			cl := client.New(seedBytes, counters, approver)
			mode := transport.Mode(transportFlag)
			if mode == "" {
				defaultMode, _ := transport.TransportOptions()
				mode = defaultMode
			}
			if deviceName == "" {
				deviceName = "Virtual FIDO"
			}
			if deferredStart {
				fmt.Println("Waiting for 'insert' command via stdin...")
				for sig := range approver.signalChan {
					if sig == "insert" {
						break
					}
				}
			}
			transport.Start(mode, cl, deviceName)
			return nil
		},
	}
	cmd.Flags().StringVar(&seedFile, "seed-file", "",
		"path to hex-encoded seed (if empty, read from stdin)")
	cmd.Flags().StringVar(&countersPath, "counters", "",
		"path to encrypted counter store (optional; defaults to time-based)")
	defaultTransport, transportOptions := transport.TransportOptions()
	cmd.Flags().StringVar(&transportFlag, "transport", string(defaultTransport), "transport: "+transportOptions)
	cmd.Flags().StringVar(&deviceName, "device-name", "Virtual FIDO", "UHID/USB device name")
	cmd.Flags().BoolVar(&alwaysApprove, "always-approve", false, "Always approve FIDO requests")
	cmd.Flags().BoolVar(&autoSelect, "auto-select", false, "Auto-select first identity if multiple are found")
	cmd.Flags().StringVar(&signalFile, "signal-file", "", "Path to the approval signal file")
	cmd.Flags().BoolVar(&deferredStart, "deferred-start", false, "Wait for 'insert' command before starting transport")
	return cmd
}

type promptApprover struct {
	alwaysApprove bool
	autoSelect    bool
	signalFile    string
	signalChan    chan string
}

func newPromptApprover(alwaysApprove, autoSelect bool, signalFile string, readStdin bool) *promptApprover {
	p := &promptApprover{
		alwaysApprove: alwaysApprove,
		autoSelect:    autoSelect,
		signalFile:    signalFile,
		signalChan:    make(chan string, 10),
	}
	if readStdin {
		go p.runSignaling()
	}
	return p
}

func (p *promptApprover) FeedSignal(sig string) {
	select {
	case p.signalChan <- strings.ToLower(strings.TrimSpace(sig)):
	default:
		// Channel full, drop or log?
	}
}

func (p *promptApprover) runSignaling() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if line == "" {
			continue
		}
		p.signalChan <- line
	}
}

func notifyDesktop(title, body string, timeoutMs int) {
	go func() {
		_ = exec.Command(
			"gdbus", "call", "--session",
			"--dest", "org.freedesktop.Notifications",
			"--object-path", "/org/freedesktop/Notifications",
			"--method", "org.freedesktop.Notifications.Notify",
			"Virtual FIDO", "0", "security-high",
			title, body, "[]", "{}", strconv.Itoa(timeoutMs),
		).Run()
	}()
}

func (p *promptApprover) waitApproval(timeout time.Duration) bool {
	if p.alwaysApprove {
		return true
	}

	var pendingFile string
	if p.signalFile != "" {
		// Remove any stale touch signal that arrived more than 1.5s before this prompt started
		if st, err := os.Stat(p.signalFile); err == nil && time.Since(st.ModTime()) > 1500*time.Millisecond {
			_ = os.Remove(p.signalFile)
		}
		pendingFile = filepath.Join(filepath.Dir(p.signalFile), "pending.prompt")
		_ = os.WriteFile(pendingFile, []byte(time.Now().Format(time.RFC3339Nano)+"\n"), 0o600)
		defer func() { _ = os.Remove(pendingFile) }()
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case sig := <-p.signalChan:
			if sig == "touch" || sig == "approve" || sig == "y" || sig == "yes" || sig == "" {
				return true
			}
			if sig == "n" || sig == "no" || sig == "deny" {
				return false
			}
		case <-ticker.C:
			if p.signalFile != "" {
				if _, err := os.Stat(p.signalFile); err == nil {
					_ = os.Remove(p.signalFile)
					return true
				}
			}
		case <-timer.C:
			return false
		}
	}
}

func (p *promptApprover) ApproveClientAction(
	action fido_client.ClientAction,
	params fido_client.ClientActionRequestParams) (bool, int) {
	rp := params.RelyingParty
	if rp == "" {
		rp = "<unknown-rp>"
	}
	user := params.UserName
	if user == "" {
		user = "<unknown-user>"
	}
	switch action {
	case fido_client.ClientActionFIDOMakeCredential:
		fmt.Printf("Approval Required: Register for %q. Type 'touch' or 'y' to approve.\n", rp)
		if p.signalFile != "" {
			notifyDesktop("Fingerprint / FIDO2 Touch Required", fmt.Sprintf("Registering %s — trigger touch signal to approve", rp), 15000)
		}
		ok := p.waitApproval(30 * time.Second)
		if ok {
			fmt.Printf("Approved registration for %q\n", rp)
			if p.signalFile != "" {
				notifyDesktop("Fingerprint Approved", fmt.Sprintf("Approved registration for %s", rp), 3000)
			}
		} else {
			fmt.Printf("Denied registration for %q\n", rp)
		}
		return ok, 0
	case fido_client.ClientActionFIDOGetAssertion:
		if len(params.Options) > 1 {
			if p.autoSelect {
				fmt.Printf("Auto-selected first identity for %q: %q\n", rp, params.Options[0])
				return true, 0
			}
			fmt.Printf("Multiple identities found for %q:\n", rp)
			for i, opt := range params.Options {
				fmt.Printf("[%d] %s\n", i, opt)
			}
			fmt.Println("Select identity index (0-N) or 'n' to deny:")
			for {
				select {
				case sig := <-p.signalChan:
					if strings.ToLower(sig) == "n" {
						fmt.Printf("Denied identity selection for %q\n", rp)
						return false, 0
					}
					idx, err := strconv.Atoi(sig)
					if err == nil && idx >= 0 && idx < len(params.Options) {
						fmt.Printf("Selected identity for %q: %q\n", rp, params.Options[idx])
						return true, idx
					}
					fmt.Println("Invalid selection. Please try again.")
				case <-time.After(15 * time.Second):
					fmt.Printf("Timeout waiting for identity selection for %q\n", rp)
					return false, 0
				}
			}
		}

		fmt.Printf("Approval Required: Login for %q user %q. Type 'touch' or 'y' to approve.\n", rp, user)
		if p.signalFile != "" {
			notifyDesktop("Fingerprint / FIDO2 Touch Required", fmt.Sprintf("Sign in to %s (%s) — trigger touch signal to approve", rp, user), 15000)
		}
		ok := p.waitApproval(30 * time.Second)
		if ok {
			fmt.Printf("Approved login for %q user %q\n", rp, user)
			if p.signalFile != "" {
				notifyDesktop("Fingerprint Approved", fmt.Sprintf("Approved sign-in for %s (%s)", rp, user), 3000)
			}
		} else {
			fmt.Printf("Denied login for %q user %q\n", rp, user)
		}
		return ok, 0
	case fido_client.ClientActionU2FRegister:
		fmt.Println("Approval Required: U2F registration. Type 'touch' or 'y' to approve.")
		if p.signalFile != "" {
			notifyDesktop("Fingerprint / FIDO2 Touch Required", "U2F registration — trigger touch signal to approve", 15000)
		}
		ok := p.waitApproval(30 * time.Second)
		return ok, 0
	case fido_client.ClientActionU2FAuthenticate:
		fmt.Println("Approval Required: U2F authentication. Type 'touch' or 'y' to approve.")
		if p.signalFile != "" {
			notifyDesktop("Fingerprint / FIDO2 Touch Required", "U2F authentication — trigger touch signal to approve", 15000)
		}
		ok := p.waitApproval(30 * time.Second)
		return ok, 0
	}
	return false, 0
}

func onlineOnlyCmd() *cobra.Command {
	var transportFlag string
	var deviceName string
	cmd := &cobra.Command{
		Use:   "online-only",
		Short: "Run online relay mode (air-gapped flow)",
		RunE: func(cmd *cobra.Command, args []string) error {
			mode := transport.Mode(transportFlag)
			switch mode {
			case transport.ModeUHID:
				if deviceName == "" {
					deviceName = "Virtual FIDO (relay)"
				}
				return runOnlineUHID(deviceName)
			case transport.ModeDarwin:
				return runOnlineDarwin()
			case transport.ModeUSBIP, transport.ModeUSBIPWin2:
				return runOnlineUSBIP(mode)
			default:
				_, options := transport.TransportOptions()
				return fmt.Errorf("unknown transport %q; expected %s", transportFlag, options)
			}
		},
	}
	defaultTransport, transportOptions := transport.TransportOptions()
	cmd.Flags().StringVar(&transportFlag, "transport", string(defaultTransport),
		"transport: "+transportOptions)
	cmd.Flags().StringVar(&deviceName, "device-name", "Virtual FIDO (relay)",
		"UHID device name")
	return cmd
}

func offlineOnlyCmd() *cobra.Command {
	var seedFile string
	var countersPath string
	cmd := &cobra.Command{
		Use:   "offline-only",
		Short: "Process online-only requests using seed and vault",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runOfflineVault(seedFile, countersPath)
		},
	}
	cmd.Flags().StringVar(&seedFile, "seed-file", "",
		"path to hex seed (if empty, stdin)")
	cmd.Flags().StringVar(&countersPath, "counters", "",
		"path to encrypted counter store (optional; defaults to time-based)")
	cmd.Flags().BoolVar(&autoApprove, "auto-approve", false,
		"Auto-approve all requests")
	return cmd
}

func buildResponse(req *airgap.Request, cl *client.SeedClient) (*airgap.Response, error) {
	switch req.Op {
	case airgap.OpMakeCredential:
		params := []webauthn.PublicKeyCredentialParams{{Type: "public-key", Algorithm: cose.COSE_ALGORITHM_ID_ES256}}
		rp := &webauthn.PublicKeyCredentialRPEntity{ID: req.RPID, Name: req.RPID}
		user := &webauthn.PublicKeyCrendentialUserEntity{ID: req.UserHandle, Name: "user", DisplayName: "user"}
		cs := cl.NewCredentialSource(params, nil, rp, user)
		if cs == nil {
			return nil, fmt.Errorf("failed to create credential")
		}
		flags := byte(0x05) // UP + UV
		resp := ctap.BuildMakeCredentialResponse(cs, req.ClientDataHash, flags)
		return &airgap.Response{
			Op:                req.Op,
			CredentialID:      cs.ID,
			AuthenticatorData: resp.AuthData,
			AttestationObject: util.MarshalCBOR(resp),
		}, nil
	case airgap.OpGetAssertion:
		if len(req.AllowList) == 0 {
			return nil, fmt.Errorf("allowList required")
		}
		allow := []webauthn.PublicKeyCredentialDescriptor{{Type: "public-key", ID: req.AllowList[0]}}
		cs := cl.GetAssertionSource(req.RPID, allow)
		if cs == nil {
			return nil, fmt.Errorf("no credential")
		}
		flags := byte(0x05) // UP + UV
		ar := ctap.BuildGetAssertionResponse(cs, req.RPID, req.ClientDataHash, flags)
		return &airgap.Response{
			Op:                req.Op,
			CredentialID:      cs.ID,
			AuthenticatorData: ar.AuthenticatorData,
			Signature:         ar.Signature,
			UserHandle:        req.UserHandle,
			SignCount:         uint32(cs.SignatureCounter),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported op %d", req.Op)
	}
}

type offlineProxy struct {
	kind   airgap.HIDKind
	reader *bufio.Reader
}

func (p *offlineProxy) HandleMessage(data []byte) []byte {
	if p.kind == airgap.HIDKindCTAP && len(data) > 0 && data[0] == 0x04 {
		return buildStaticGetInfo()
	}
	meta := summarizeRequest(p.kind, data)
	req := &airgap.HIDRequest{
		Kind:     p.kind,
		Command:  data[0],
		Payload:  data,
		RPID:     meta.rpID,
		User:     meta.user,
		Op:       meta.op,
		AllowLen: meta.allowLen,
	}
	hexReq, _ := airgap.EncodeHIDRequest(req)
	fmt.Println("Request hex (send to offline-only):")
	fmt.Println(hexReq)
	fmt.Println("Paste response hex from offline-only (or press Enter to deny/skip):")
	line, _ := p.reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		// Deny/skip
		if p.kind == airgap.HIDKindCTAP {
			return []byte{0x27} // ctap2ErrOperationDenied
		}
		// U2F conditions not satisfied (0x6985)
		return util.ToBE(uint16(0x6985))
	}
	resp, err := airgap.DecodeHIDResponse(line)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decode response: %v\n", err)
		if p.kind == airgap.HIDKindCTAP {
			return []byte{0x27}
		}
		return util.ToBE(uint16(0x6985))
	}
	if resp.Error != "" {
		if p.kind == airgap.HIDKindCTAP {
			return []byte{0x27}
		}
		return util.ToBE(uint16(0x6985))
	}
	return resp.Payload
}

type requestMeta struct {
	rpID     string
	user     string
	op       string
	allowLen int
}

func summarizeRequest(kind airgap.HIDKind, data []byte) requestMeta {
	if kind == airgap.HIDKindCTAP && len(data) > 0 {
		cmd := data[0]
		switch cmd {
		case 0x01: // makeCredential
			args, err := ctap.DecodeMakeCredentialArgs(data[1:])
			if err == nil && args.RP != nil {
				userName := ""
				if args.User != nil {
					userName = args.User.Name
				}
				return requestMeta{rpID: args.RP.ID, user: userName, op: "makeCredential", allowLen: len(args.ExcludeList)}
			}
		case 0x02: // getAssertion
			args, err := ctap.DecodeGetAssertionArgs(data[1:])
			if err == nil {
				return requestMeta{rpID: args.RPID, user: "", op: "getAssertion", allowLen: len(args.AllowList)}
			}
		}
	}
	return requestMeta{}
}

func handleLocal(report []byte) (bool, []byte) {
	if len(report) < 7 {
		return false, nil
	}
	cmd := report[4]
	switch cmd {
	case 0x81: // PING
		return true, report
	case 0xBB: // KEEPALIVE
		return true, nil
	default:
		return false, nil
	}
}

func buildStaticGetInfo() []byte {
	resp := map[int]interface{}{
		1: []string{"FIDO_2_0", "U2F_V2"},
		3: ctap.DefaultAAGUID,
		4: map[string]bool{
			"plat": false,
			"rk":   false,
			"up":   true,
		},
	}
	payload := util.MarshalCBOR(resp)
	return append([]byte{0x00}, payload...)
}
func runOnlineUHID(name string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		cancel()
	}()

	dev, err := uhid.Open(name, uhid.ReportDescriptorFIDO)
	if err != nil {
		return err
	}
	defer dev.Close()
	dev.WaitReady()
	go func() {
		<-ctx.Done()
		_ = dev.Close()
	}()

	fmt.Printf("Online-only UHID relay started as %q. "+
		"Copy request hex to offline-only and paste responses back.\n", name)
	reader := bufio.NewReader(os.Stdin)

	ctapProxy := &offlineProxy{kind: airgap.HIDKindCTAP, reader: reader}
	u2fProxy := &offlineProxy{kind: airgap.HIDKindU2F, reader: reader}
	hidServer := ctap_hid.NewCTAPHIDServer(ctapProxy, u2fProxy)
	hidServer.SetResponseHandler(func(resp []byte) {
		if ctx.Err() != nil {
			return
		}
		_ = dev.WriteReport(ctx, resp)
	})

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		report, err := dev.ReadReport(ctx)
		if err != nil {
			return err
		}
		if handled, resp := handleLocal(report); handled {
			if resp != nil {
				_ = dev.WriteReport(ctx, resp)
			}
			continue
		}
		hidServer.HandleMessage(report)
	}
}

func runOnlineUSBIP(mode transport.Mode) error {
	ctapProxy := &offlineProxy{kind: airgap.HIDKindCTAP, reader: bufio.NewReader(os.Stdin)}
	u2fProxy := &offlineProxy{kind: airgap.HIDKindU2F, reader: bufio.NewReader(os.Stdin)}
	hidServer := ctap_hid.NewCTAPHIDServer(ctapProxy, u2fProxy)
	usbDevice := usb.NewUSBDevice(hidServer)
	server := usbip.NewUSBIPServer([]usbip.USBIPDevice{usbDevice})

	go server.Start()
	time.Sleep(500 * time.Millisecond)

	var err error
	switch mode {
	case transport.ModeUSBIP:
		err = transport.AttachUSBIP()
	case transport.ModeUSBIPWin2:
		err = transport.AttachUSBIPWin2()
	default:
		err = fmt.Errorf("unsupported usbip transport %q", mode)
	}
	if err != nil {
		return err
	}
	select {}
}

var autoApprove bool

func runOfflineVault(seedFile, vaultPath string) error {
	seedBytes, err := seed.Load(seedFile)
	if err != nil {
		return fmt.Errorf("load seed: %w", err)
	}
	var counters client.CounterState
	if vaultPath == "" {
		fmt.Println("Using in-memory time-based counters")
		counters = state.NewTimeBasedCounterStore(0, nil)
	} else {
		store := state.NewStore(vaultPath, seedBytes)
		cs, err := state.NewCounterStore(store)
		if err != nil {
			return fmt.Errorf("load vault: %w", err)
		}
		fmt.Println("Loaded vault:")
		fmt.Print(cs.String())
		counters = cs
	}
	approver := newPromptApprover(autoApprove, false, "", false)
	cl := client.New(seedBytes, counters, approver)

	ctapServer := ctap.NewCTAPServer(cl)
	u2fServer := u2f.NewU2FServer(cl)

	fmt.Println("Paste request hex blobs from online-only; Ctrl+D to exit.")
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		req, err := airgap.DecodeHIDRequest(line)
		if err != nil {
			approver.FeedSignal(line)
			continue
		}
		if req.Op != "" || req.RPID != "" {
			fmt.Printf("Request: kind=%d op=%s rp=%s user=%s allow=%d\n", req.Kind, req.Op, req.RPID, req.User, req.AllowLen)
		}
		if !autoApprove && !airgap.PromptYesNo("Approve? (Y/n)") {
			respHex, _ := airgap.EncodeHIDResponse(&airgap.HIDResponse{Error: "denied"})
			fmt.Println(respHex)
			continue
		}
		var payload []byte
		switch req.Kind {
		case airgap.HIDKindCTAP:
			payload = ctapServer.HandleMessage(req.Payload)
		case airgap.HIDKindU2F:
			payload = u2fServer.HandleMessage(req.Payload)
		default:
			fmt.Fprintf(os.Stderr, "unknown request kind %d\n", req.Kind)
			continue
		}
		respHex, err := airgap.EncodeHIDResponse(&airgap.HIDResponse{Payload: payload})
		if err != nil {
			fmt.Fprintf(os.Stderr, "encode response: %v\n", err)
			continue
		}
		fmt.Println(respHex)
	}
	return scanner.Err()
}
