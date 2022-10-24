// Package cmd contains the cobra command line setup
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "mev-boost-relay",
	Short: "mev-boost-relay " + Version,
	Long:  `https://github.com/flashbots/mev-boost-relay`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("mev-boost-relay %s\n", Version)
		_ = cmd.Help()
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
