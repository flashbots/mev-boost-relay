// Package cmd contains the cobra command line setup
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "relay",
	Short: "mev-boost relay",
	Long:  `https://github.com/flashbots/boost-relay`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
