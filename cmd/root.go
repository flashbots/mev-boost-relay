// Package cmd contains the cobra command line setup
package cmd

import (
	"os"
	"os/signal"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "relay",
	Short: "mev-boost relay",
	Long:  `https://github.com/flashbots/mev-boost-relay`,
}

func Execute() {
	// if err := rootCmd.Execute(); err != nil {
	// 	fmt.Println(err)
	// 	os.Exit(1)
	// }
	go apiCmd.Execute()
	go websiteCmd.Execute()
	go housekeeperCmd.Execute()
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	for {
		<-c
		os.Exit(1)
	}

}
