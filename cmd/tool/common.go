// Package tool exports tool subcommands
package tool

import "github.com/flashbots/mev-boost-relay/common"

var (
	log                = common.LogSetup(false, "info")
	defaultPostgresDSN = common.GetEnv("POSTGRES_DSN", "")

	postgresDSN string
	outFiles    []string

	idFirst   uint64
	idLast    uint64
	dateStart string
	dateEnd   string
)
