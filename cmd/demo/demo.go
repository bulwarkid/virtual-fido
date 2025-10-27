package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	virtual_fido "github.com/bulwarkid/virtual-fido"
	"github.com/bulwarkid/virtual-fido/fido_client"
	"github.com/bulwarkid/virtual-fido/identities"
	"github.com/bulwarkid/virtual-fido/util"
	"github.com/spf13/cobra"
)

var vaultFilename string
var vaultPassphrase string
var identityID string
var verbose bool
var exportIdentity string
var exportOutput string
var exportAll bool
var exportFormat string
var exportOutputDir string
var fingerprintUser string

func checkErr(err error, message string) {
	if err != nil {
		panic(fmt.Sprintf("Error: %s - %s", err, message))
	}
}

func listIdentities(cmd *cobra.Command, args []string) {
	client := createClient()
	fmt.Printf("------- Identities in file '%s' -------\n", vaultFilename)
	sources := client.Identities()
	for _, source := range sources {
		fmt.Printf("(%s): '%s' for website '%s'\n", hex.EncodeToString(source.ID[:4]), source.User.Name, source.RelyingParty.Name)
	}
}

func deleteIdentity(cmd *cobra.Command, args []string) {
	client := createClient()
	ids := client.Identities()
	targetIDs := make([]*identities.CredentialSource, 0)
	for _, id := range ids {
		hexString := hex.EncodeToString(id.ID)
		if strings.HasPrefix(hexString, identityID) {
			targetIDs = append(targetIDs, &id)
		}
	}
	if len(targetIDs) > 1 {
		fmt.Printf("Multiple identities with prefix (%s):\n", identityID)
		for _, id := range targetIDs {
			fmt.Printf("- (%s)\n", hex.EncodeToString(id.ID))
		}
	} else if len(targetIDs) == 1 {
		fmt.Printf("Deleting identity (%s)\n...", hex.EncodeToString(targetIDs[0].ID))
		if client.DeleteIdentity(targetIDs[0].ID) {
			fmt.Printf("Done.\n")
		} else {
			fmt.Printf("Could not find (%s).\n", hex.EncodeToString(targetIDs[0].ID))
		}
	} else {
		fmt.Printf("No identity found with prefix (%s)\n", identityID)
	}
}

func exportPasskeys(cmd *cobra.Command, args []string) {
	if exportAll && exportIdentity != "" {
		cmd.PrintErrln("Cannot specify both --all and --identity")
		return
	}
	if !exportAll && exportIdentity == "" {
		cmd.PrintErrln("Must provide an identity prefix with --identity or use --all")
		return
	}
	if exportFormat != "archive" && exportFormat != "keepassxc" {
		cmd.Printf("Unknown export format %q\n", exportFormat)
		return
	}
	client := createClient()
	ids := client.Identities()
	if len(ids) == 0 {
		cmd.Println("No identities available to export")
		return
	}

	selected := make([]identities.CredentialSource, 0, len(ids))
	if exportAll {
		selected = append(selected, ids...)
	} else {
		for _, id := range ids {
			if strings.HasPrefix(hex.EncodeToString(id.ID), exportIdentity) {
				selected = append(selected, id)
			}
		}
		if len(selected) == 0 {
			cmd.Printf("No identity found with prefix (%s)\n", exportIdentity)
			return
		}
	}

	switch exportFormat {
	case "archive":
		exportData, err := identities.ExportPasskeysArchive(selected, identities.PasskeyExportMetadata{
			Exporter:        "virtual-fido-demo",
			ExporterVersion: "demo",
		})
		if err != nil {
			cmd.Printf("Failed to export passkeys: %v\n", err)
			return
		}
		if err := os.WriteFile(exportOutput, exportData, 0600); err != nil {
			cmd.Printf("Could not write passkey file: %v\n", err)
			return
		}
		cmd.Printf("Exported %d passkey(s) to %s\n", len(selected), exportOutput)
	case "keepassxc":
		if len(selected) == 1 {
			if exportOutputDir != "" {
				if err := os.MkdirAll(exportOutputDir, 0700); err != nil {
					cmd.Printf("Could not create output directory: %v\n", err)
					return
				}
				exportOutput = filepath.Join(exportOutputDir, fmt.Sprintf("%s.passkey", makePasskeyFilename(selected[0])))
			}
			exportData, err := identities.ExportKeePassPasskey(selected[0])
			if err != nil {
				cmd.Printf("Failed to export passkey: %v\n", err)
				return
			}
			if err := os.WriteFile(exportOutput, exportData, 0600); err != nil {
				cmd.Printf("Could not write passkey file: %v\n", err)
				return
			}
			cmd.Printf("Exported KeePassXC passkey to %s\n", exportOutput)
			return
		}

		if exportOutputDir == "" {
			cmd.PrintErrln("KeePassXC export for multiple identities requires --output-dir")
			return
		}
		if err := os.MkdirAll(exportOutputDir, 0700); err != nil {
			cmd.Printf("Could not create output directory: %v\n", err)
			return
		}
		for _, source := range selected {
			exportData, err := identities.ExportKeePassPasskey(source)
			if err != nil {
				cmd.Printf("Failed to export passkey (%s): %v\n", hex.EncodeToString(source.ID), err)
				return
			}
			filename := fmt.Sprintf("%s.passkey", makePasskeyFilename(source))
			targetPath := filepath.Join(exportOutputDir, filename)
			if err := os.WriteFile(targetPath, exportData, 0600); err != nil {
				cmd.Printf("Could not write passkey file %s: %v\n", targetPath, err)
				return
			}
		}
		cmd.Printf("Exported %d KeePassXC passkeys to %s\n", len(selected), exportOutputDir)
	}
}

func enablePIN(cmd *cobra.Command, args []string) {
	client := createClient()
	client.EnablePIN()
	cmd.Println("PIN enabled")
}

func disablePIN(cmd *cobra.Command, args []string) {
	client := createClient()
	client.DisablePIN()
	cmd.Println("PIN disabled")
}

var newPIN string

func setPIN(cmd *cobra.Command, args []string) {
	pin := strings.TrimSpace(newPIN)
	if len(pin) < 4 {
		cmd.PrintErr("Invalid PIN: PIN must be at least 4 characters")
		return
	}
	for _, r := range pin {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			continue
		}
		cmd.PrintErr("Invalid PIN: Only digits and letters are allowed")
		return
	}
	client := createClient()
	client.SetPIN([]byte(pin))
	cmd.Println("PIN set")
}

func enableFingerprint(cmd *cobra.Command, args []string) {
	client := createClient()
	if !client.FingerprintAvailable() {
		for _, hint := range fingerprintAvailabilityHints() {
			cmd.PrintErrln(hint)
		}
		return
	}
	if !client.VerifyUser(fido_client.ClientActionManageAuthenticator, fido_client.ClientActionRequestParams{}) {
		cmd.PrintErrln("Fingerprint check failed; fingerprint remains disabled.")
		return
	}
	client.EnableFingerprint()
	cmd.Println("Fingerprint verification enabled")
}

func disableFingerprint(cmd *cobra.Command, args []string) {
	client := createClient()
	client.DisableFingerprint()
	cmd.Println("Fingerprint verification disabled")
}

func fingerprintStatus(cmd *cobra.Command, args []string) {
	client := createClient()
	state := "disabled"
	if client.FingerprintEnabled() {
		state = "enabled"
	}
	availability := "available"
	if !client.FingerprintAvailable() {
		availability = "unavailable"
	}
	cmd.Printf("Fingerprint verification is %s (system %s)\n", state, availability)
}

func start(cmd *cobra.Command, args []string) {
	client := createClient()
	runServer(client)
}

func createClient() *fido_client.DefaultFIDOClient {
	// ALL OF THIS IS INSECURE, FOR TESTING PURPOSES ONLY
	caPrivateKey, err := identities.CreateCAPrivateKey()
	checkErr(err, "Could not generate attestation CA private key")
	certificateAuthority, err := identities.CreateSelfSignedCA(caPrivateKey)
	encryptionKey := sha256.Sum256([]byte("test"))

	virtual_fido.SetLogOutput(os.Stdout)
	if verbose {
		virtual_fido.SetLogLevel(util.LogLevelTrace)
	} else {
		virtual_fido.SetLogLevel(util.LogLevelDebug)
	}
	support := ClientSupport{vaultFilename: vaultFilename, vaultPassphrase: vaultPassphrase}
	if fingerprintUser != "" {
		support.fingerprintUser = fingerprintUser
	}
	// Disable PIN by default for maximum compatibility; can be enabled via CLI later
	return fido_client.NewDefaultClient(certificateAuthority, caPrivateKey, encryptionKey, false, &support, &support, &support)
}

var rootCmd = &cobra.Command{
	Use:   "demo",
	Short: "Run Virtual FIDO demo",
	Long: `demo attaches a virtual FIDO2 authenticator and manages stored credentials.

Common tasks:
  • demo export --format archive --all --output passkeys.passkey
      Export all credentials as a .passkey ZIP bundle.
  • demo export --format keepassxc --identity abcd --output-dir ./passkeys
      Export passkeys as KeePassXC-compatible JSON files (one per identity).
  • node scripts/export_aegis_otpauth.js --vault vault.json --passphrase passphrase --out export_otpauth.txt
      Generate Base32-wrapped credential blobs as otpauth:// URIs (text file).
  • node scripts/export_aegis_qr.js --vault vault.json --passphrase passphrase --out-dir ./qr_codes
      Render passkey payloads as QR codes for transfer to other devices.
  • demo pin enable | demo pin set --pin 1234
      Enable or assign a 4+ character PIN (letters/digits) for the virtual authenticator.`,
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&vaultFilename, "vault", "", "vault.json", "Identity vault filename")
	rootCmd.PersistentFlags().StringVarP(&vaultPassphrase, "passphrase", "", "passphrase", "Identity vault passphrase")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")
	rootCmd.PersistentFlags().StringVar(&fingerprintUser, "fingerprint-user", "", "Override system user for fingerprint verification (default: current user)")
	rootCmd.MarkFlagRequired("vault")
	rootCmd.MarkFlagRequired("passphrase")
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	start := &cobra.Command{
		Use:   "start",
		Short: "Attach virtual FIDO device",
		Run:   start,
	}
	rootCmd.AddCommand(start)

	list := &cobra.Command{
		Use:   "list",
		Short: "List identities in vault",
		Run:   listIdentities,
	}
	rootCmd.AddCommand(list)

	delete := &cobra.Command{
		Use:   "delete",
		Short: "Delete identity in vault",
		Run:   deleteIdentity,
	}
	delete.Flags().StringVar(&identityID, "identity", "", "Identity hash to delete")
	delete.MarkFlagRequired("identity")
	rootCmd.AddCommand(delete)

	exportCommand := &cobra.Command{
		Use:   "export",
		Short: "Export passkeys to a .passkey file",
		Long: `Export credentials from the vault.

Examples:
  demo export --all --format archive --output passkeys.passkey
      Bundle all credentials into a single .passkey archive.
  demo export --identity deadbeef --format keepassxc --output github.passkey
      Export one credential as KeePassXC JSON (PEM private key).
  demo export --all --format keepassxc --output-dir ./passkeys
      Emit one KeePassXC .passkey file per credential into the target folder.`,
		Run: exportPasskeys,
	}
	exportCommand.Flags().StringVar(&exportIdentity, "identity", "", "Identity hash prefix to export")
	exportCommand.Flags().BoolVar(&exportAll, "all", false, "Export all identities")
	exportCommand.Flags().StringVar(&exportOutput, "output", "passkeys.passkey", "Output .passkey filename")
	exportCommand.Flags().StringVar(&exportFormat, "format", "archive", "Export format: archive | keepassxc")
	exportCommand.Flags().StringVar(&exportOutputDir, "output-dir", "", "Output directory for multi-file exports (keepassxc)")
	rootCmd.AddCommand(exportCommand)

	pinCommand := &cobra.Command{
		Use:   "pin",
		Short: "Modify PIN behavior",
		Long: `Manage the device PIN.

Usage:
  demo pin enable            Enable PIN protection (prompts during authentications).
  demo pin disable           Turn off PIN protection.
  demo pin set --pin 1234    Assign a new PIN (>=4 characters).`,
	}
	enablePINCommand := &cobra.Command{
		Use:   "enable",
		Short: "Enables PIN protection",
		Run:   enablePIN,
	}
	pinCommand.AddCommand(enablePINCommand)
	disablePINCommand := &cobra.Command{
		Use:   "disable",
		Short: "Disables PIN protection",
		Run:   disablePIN,
	}
	pinCommand.AddCommand(disablePINCommand)
	setPINCommand := &cobra.Command{
		Use:   "set",
		Short: "Sets the PIN",
		Run:   setPIN,
	}
	setPINCommand.Flags().StringVar(&newPIN, "pin", "", "New PIN (>=4 characters, letters and digits only)")
	setPINCommand.MarkFlagRequired("pin")
	pinCommand.AddCommand(setPINCommand)
	rootCmd.AddCommand(pinCommand)

	fingerprintCommand := &cobra.Command{
		Use:   "fingerprint",
		Short: "Manage fingerprint verification",
		Long: `Manage biometric user verification.

Usage:
  demo fingerprint enable           Enable fingerprint verification (requires system fingerprint support).
  demo fingerprint disable          Disable fingerprint verification.
  demo fingerprint status           Show current fingerprint state and availability.`,
	}
	enableFingerprintCommand := &cobra.Command{
		Use:   "enable",
		Short: "Enable fingerprint verification",
		Run:   enableFingerprint,
	}
	fingerprintCommand.AddCommand(enableFingerprintCommand)
	disableFingerprintCommand := &cobra.Command{
		Use:   "disable",
		Short: "Disable fingerprint verification",
		Run:   disableFingerprint,
	}
	fingerprintCommand.AddCommand(disableFingerprintCommand)
	statusFingerprintCommand := &cobra.Command{
		Use:   "status",
		Short: "Show fingerprint verification status",
		Run:   fingerprintStatus,
	}
	fingerprintCommand.AddCommand(statusFingerprintCommand)
	rootCmd.AddCommand(fingerprintCommand)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func makePasskeyFilename(source identities.CredentialSource) string {
	base := safeName(source.RelyingParty.ID)
	user := safeName(source.User.Name)
	if base == "" {
		base = "passkey"
	}
	if user != "" {
		base = fmt.Sprintf("%s_%s", base, user)
	}
	return fmt.Sprintf("%s_%s", base, hex.EncodeToString(source.ID[:4]))
}

func safeName(input string) string {
	input = strings.TrimSpace(strings.ToLower(input))
	if input == "" {
		return ""
	}
	var builder strings.Builder
	for _, r := range input {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			builder.WriteRune(r)
			continue
		}
		switch r {
		case '-', '_':
			builder.WriteRune(r)
		case '.':
			builder.WriteRune('-')
		default:
			builder.WriteRune('_')
		}
	}
	return strings.Trim(builder.String(), "_-")
}
