package main

import (
	"github.com/flashbots/mev-boost-relay/cmd"
)

var Version = "dev" // is set during build process

func main() {
	cmd.Version = Version
	cmd.Execute()
}
