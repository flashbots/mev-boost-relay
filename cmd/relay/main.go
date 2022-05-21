package main

import (
	"flag"

	"github.com/sirupsen/logrus"
)

var (
	version = "dev" // is set during build process

// 	// defaults
// 	defaultHost = getEnv("BOOST_HOST", "localhost")
// 	defaultPort = getEnvInt("BOOST_PORT", 18550)

// 	defaultRelayURLs                  = getEnv("RELAY_URLS", "127.0.0.1:28545") // can be IP@PORT, PUBKEY@IP:PORT, https://IP, etc.
// 	defaultRelayTimeoutMs             = getEnvInt("RELAY_TIMEOUT_MS", 2000)     // timeout for all the requests to the relay
// 	defaultDisableRelayCheckOnStartup = os.Getenv("RELAY_DISABLE_STARTUP_CHECK") != ""

// 	// cli flags
// 	host               = flag.String("host", defaultHost, "host for mev-boost to listen on")
// 	port               = flag.Int("port", defaultPort, "port for mev-boost to listen on")
// 	relayURLs          = flag.String("relays", defaultRelayURLs, "relay urls - single entry or comma-separated list (pubkey@ip:port)")
// 	relayTimeoutMs     = flag.Int("request-timeout", defaultRelayTimeoutMs, "timeout for requests to a relay [ms]")
// 	relayTestOnStartup = flag.Bool("request-check", !defaultDisableRelayCheckOnStartup, "whether to check the relays on startup, and exit if any of them is not reachable")
)

var log = logrus.WithField("module", "cmd/relay")

func main() {
	flag.Parse()
	log.Printf("boost-relay %s\n", version)
}

// 	relays := parseRelayURLs(*relayURLs)
// 	log.WithField("relays", relays).Infof("using %d relays", len(relays))

// 	if *relayTestOnStartup {
// 		relayStartupCheck(relays)
// 	}

// 	listenAddress := fmt.Sprintf("%s:%d", *host, *port)
// 	relayTimeout := time.Duration(*relayTimeoutMs) * time.Millisecond
// 	server, err := server.NewBoostService(listenAddress, relays, log, relayTimeout)
// 	if err != nil {
// 		log.WithError(err).Fatal("failed creating the server")
// 	}

// 	log.Println("listening on", listenAddress)
// 	log.Fatal(server.StartHTTPServer())
// }

// func getEnv(key string, defaultValue string) string {
// 	if value, ok := os.LookupEnv(key); ok {
// 		return value
// 	}
// 	return defaultValue
// }

// func getEnvInt(key string, defaultValue int) int {
// 	if value, ok := os.LookupEnv(key); ok {
// 		val, err := strconv.Atoi(value)
// 		if err == nil {
// 			return val
// 		}
// 	}
// 	return defaultValue
// }

// func parseRelayURLs(relayURLs string) []*server.BuilderEntry {
// 	ret := []*server.BuilderEntry{}
// 	for _, entry := range strings.Split(relayURLs, ",") {
// 		relay, err := server.NewBuilderEntry(entry)
// 		if err != nil {
// 			log.WithError(err).WithField("relayURL", entry).Fatal("Invalid relay URL")
// 		}
// 		ret = append(ret, relay)
// 	}
// 	return ret
// }

// func relayStartupCheck(relays []*server.BuilderEntry) error {

// }
