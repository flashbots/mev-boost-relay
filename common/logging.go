package common

import (
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

func LogSetup(json bool, logLevel string) *logrus.Entry {
	log := logrus.NewEntry(logrus.New())
	log.Logger.SetOutput(os.Stdout)

	if json {
		log.Logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339Nano,
		})
	} else {
		log.Logger.SetFormatter(&logrus.TextFormatter{
			TimestampFormat: time.RFC3339Nano,
			FullTimestamp:   true,
		})
	}

	if logLevel != "" {
		lvl, err := logrus.ParseLevel(logLevel)
		if err != nil {
			log.Fatalf("Invalid loglevel: %s", logLevel)
		}
		log.Logger.SetLevel(lvl)
	}
	return log
}
