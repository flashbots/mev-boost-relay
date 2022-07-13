package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var Version = "dev" // is set during build process

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number the relay application",
	Long:  `All software has versions. This is the boost relay's`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("boost-relay %s\n", Version)
	},
}
