package cmd

import (
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(monoCmd)
	rootCmd.AddCommand(apiCmd)
	rootCmd.AddCommand(websiteCmd)
	rootCmd.AddCommand(housekeeperCmd)
}

var monoCmd = &cobra.Command{
	Use:   "mono",
	Short: "Start the API server",
	Run: func(cmd *cobra.Command, args []string) {
		go websiteCmd.Run(cmd, args)
		go housekeeperCmd.Run(cmd, args)
		apiCmd.Run(cmd, args)

	},
}

func Mono() {
	monoCmd.Run(nil, nil)
}
