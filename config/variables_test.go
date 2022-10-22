package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBindAndSet(t *testing.T) {
	key := "Flashbots"
	envVar := "FLASHBOTS_URL"
	defaultValue := "https://www.flashbots.net/"
	previousValue := "https://github.com/flashbots"

	t.Run("environment variable should be empty", func(t *testing.T) {
		require.Empty(t, os.Getenv(envVar))
	})

	t.Run("should fetch default value", func(t *testing.T) {
		bindAndSet(key, envVar, defaultValue)
		require.Equal(t, defaultValue, GetString(key))
	})

	t.Run("should not overwrite previous value", func(t *testing.T) {
		t.Setenv(envVar, previousValue)
		bindAndSet(key, envVar, defaultValue)
		require.Equal(t, previousValue, GetString(key))
	})
}

func TestGetConfig(t *testing.T) {
	config := map[string]string{
		"FLASHBOTS_URL": "https://www.flashbots.net/",
		"RELAY_URL":     "https://relay.flashbots.net/",
	}
	for env, value := range config {
		bindAndSet(env, env, value)
		require.Equal(t, value, GetConfig()[env])
	}
}
