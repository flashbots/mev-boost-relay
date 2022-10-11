package cmd

import (
	"fmt"

	"github.com/flashbots/mev-boost-relay/cmd/tool"
	"github.com/spf13/cobra"
)

func init() {
	toolCmd.AddCommand(tool.DataAPIExportPayloads)
	toolCmd.AddCommand(tool.ArchiveExecutionPayloads)
	rootCmd.AddCommand(toolCmd)
}

var toolCmd = &cobra.Command{
	Use: "tool",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Error: please use a valid subcommand")
		_ = cmd.Help()
	},
}
