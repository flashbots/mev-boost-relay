package main

import (
	"flag"

	"github.com/flashbots/boost-relay/apis/builder"
	"github.com/sirupsen/logrus"
)

var (
	version = "dev" // is set during build process

	// defaults
	defaultListenAddr = "localhost:9066"

	// cli flags
	listenAddr = flag.String("listen-addr", defaultListenAddr, "listen address")
)

var log = logrus.WithField("module", "cmd/relay")

func main() {
	flag.Parse()
	log.Printf("boost-relay %s [builder-api]", version)

	srv, err := builder.NewBuilderAPIService(*listenAddr, log)
	if err != nil {
		log.WithError(err).Fatal("failed to create service")
	}

	log.Println("listening on", *listenAddr)
	log.Fatal(srv.StartHTTPServer())
}
