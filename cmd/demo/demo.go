package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
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

var newPIN int

func setPIN(cmd *cobra.Command, args []string) {
	if newPIN < 0 {
		cmd.PrintErr("Invalid PIN: PIN must be positive")
		return
	}
	newPINString := strconv.Itoa(newPIN)
	if len(newPINString) < 4 {
		cmd.PrintErr("Invalid PIN: PIN must be 4 digits")
		return
	}
	client := createClient()
	client.SetPIN([]byte(newPINString))
	cmd.Println("PIN set")
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
	return fido_client.NewDefaultClient(certificateAuthority, caPrivateKey, encryptionKey, false, &support, &support)
}

var rootCmd = &cobra.Command{
	Use:   "demo",
	Short: "Run Virtual FIDO demo",
	Long:  `demo attaches a virtual FIDO2 device for logging in with WebAuthN`,
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&vaultFilename, "vault", "", "vault.json", "Identity vault filename")
	rootCmd.PersistentFlags().StringVarP(&vaultPassphrase, "passphrase", "", "passphrase", "Identity vault passphrase")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")
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

	pinCommand := &cobra.Command{
		Use:   "pin",
		Short: "Modify PIN Behavior",
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
	setPINCommand.Flags().IntVar(&newPIN, "pin", -1, "New PIN")
	setPINCommand.MarkFlagRequired("pin")
	pinCommand.AddCommand(setPINCommand)
	rootCmd.AddCommand(pinCommand)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
