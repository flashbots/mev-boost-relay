package main

import (
	"flag"

	"github.com/flashbots/boost-relay/server"
	"github.com/flashbots/go-utils/cli"
	"github.com/sirupsen/logrus"
)

var (
	version = "dev" // is set during build process

	// defaults
	defaultListenAddr = cli.GetEnv("RELAY_LISTEN_ADDR", "localhost:9044")

	// 	// cli flags
	listenAddr = flag.String("listen-addr", defaultListenAddr, "listen address")
)

var log = logrus.WithField("module", "cmd/relay")

func main() {
	flag.Parse()
	log.Printf("boost-relay %s\n", version)

	srv, err := server.NewRelayService(*listenAddr, log)
	if err != nil {
		log.WithError(err).Fatal("failed to create service")
	}

	log.Println("listening on", *listenAddr)
	log.Fatal(srv.StartHTTPServer())
}
