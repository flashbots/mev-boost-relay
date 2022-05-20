package main

import (
	"flag"
	"os"

	"github.com/ethereum/go-ethereum/log"
)

var (
	version = "dev" // is set during build process

	// Default values
	defaultDebug   = os.Getenv("DEBUG") == "1"
	defaultLogJSON = os.Getenv("LOG_JSON") == "1"

	// Flags
	debugPtr   = flag.Bool("debug", defaultDebug, "print debug output")
	logJSONPtr = flag.Bool("log-json", defaultLogJSON, "log in JSON")
)

func main() {
	flag.Parse()

	logFormat := log.TerminalFormat(true)
	if *logJSONPtr {
		logFormat = log.JSONFormat()
	}

	logLevel := log.LvlInfo
	if *debugPtr {
		logLevel = log.LvlDebug
	}

	log.Root().SetHandler(log.LvlFilterHandler(logLevel, log.StreamHandler(os.Stderr, logFormat)))
	log.Info("Starting your-project", "version", version)

	log.Info("bye")
}
