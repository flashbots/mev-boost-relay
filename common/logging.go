package common

import (
	"log"
	"os"

	"github.com/sirupsen/logrus"
)

func LogSetup(json bool, logLevel string) {
	logrus.SetOutput(os.Stdout)

	if json {
		logrus.SetFormatter(&logrus.JSONFormatter{})
	} else {
		logrus.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
		})

	}

	if logLevel != "" {
		lvl, err := logrus.ParseLevel(logLevel)
		if err != nil {
			log.Fatalf("Invalid loglevel: %s", logLevel)
		}
		logrus.SetLevel(lvl)
	}
}
