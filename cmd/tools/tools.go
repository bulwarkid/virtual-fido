package main

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/fxamacker/cbor/v2"
	"github.com/spf13/cobra"
)

func checkErr(err error, msg string) {
	if err != nil {
		panic(fmt.Sprintf("Error: %s - %s", msg, err))
	}
}

func decodeCbor(cmd *cobra.Command, args []string) {
	b64data := args[0]
	data, err := base64.StdEncoding.DecodeString(b64data)
	checkErr(err, "Could not decode base64")
	var cborStruct interface{}
	err = cbor.Unmarshal(data, &cborStruct)
	checkErr(err, "Could not decode CBOR")
	fmt.Printf("%#v\n", cborStruct)
}

var rootCmd = &cobra.Command{
	Use:   "tools",
	Short: "Virtual FIDO Tools",
	Long:  `Virtual FIDO tools to test various FIDO-related data`,
}

func init() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	cborCommand := &cobra.Command{
		Use:   "cbor",
		Short: "Parse base64 encoded CBOR data",
		Args:  cobra.MinimumNArgs(1),
		Run:   decodeCbor,
	}
	rootCmd.AddCommand(cborCommand)

}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
