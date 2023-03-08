package datastore

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TODO: standardize integration tests to run with single flag/env var - consolidate with RUN_DB_TESTS
var runIntegrationTests = os.Getenv("RUN_INTEGRATION_TESTS") == "1"

func initMemcached(t *testing.T) *Memcached {
	t.Helper()
	if !runIntegrationTests {
		t.Skip("Skipping integration tests")
	}

	return nil
}

func TestNewMemcached(t *testing.T) {
	mem, err := NewMemcached("test")
	require.NoError(t, err, "expected no error on memcached initialization but found %v", err)
	require.NotNil(t, mem, "expected non-nil memcached instance")
}

func TestMemcachedSaveExecutionPayload(t *testing.T) {
	mem, err := NewMemcached("test")
	require.NoError(t, err, "expected no error on memcached initialization but found [%v]", err)
	require.NotNil(t, mem, "expected non-nil memcached instance")

	err = mem.SaveExecutionPayload(0, "0xfoo", "0xbeef", nil)
	require.NoError(t, err, "expected no error on memcache SaveExecutionPayload but found [%v]", err)
}

func TestMemcachedGetExecutionPayload(t *testing.T) {
	var servers []string
	if memURLs := os.Getenv("MEMCACHE_URL"); memURLs != "" {
		servers = strings.Split(memURLs, ",")
	} else {
		servers = nil
	}
	mem, err := NewMemcached("test", servers...)

	require.NoError(t, err, "expected no error on memcache initialization but found [%v]", err)
	require.NotNil(t, mem, "expected non-nil memcache instance")

	_, err = mem.GetExecutionPayload(0, "0xfoo", "0xbeef")
	require.NoError(t, err, "expected no error on memcache GetExecutionPayload but found [%v]", err)
}
