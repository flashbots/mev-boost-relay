package common

import (
	"os"

	"github.com/sirupsen/logrus"
)

// RFC3339Milli is a RFC3339 timestamp format restricted to millisecond precision.
// No standard format is provided, so we create our own.
const RFC3339Milli = "2006-01-02T15:04:05.000Z07:00"

func LogSetup(json bool, logLevel string) *logrus.Entry {
	log := logrus.NewEntry(logrus.New())
	log.Logger.SetOutput(os.Stdout)

	if json {
		log.Logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: RFC3339Milli,
		})
	} else {
		log.Logger.SetFormatter(&logrus.TextFormatter{
			TimestampFormat: RFC3339Milli,
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
