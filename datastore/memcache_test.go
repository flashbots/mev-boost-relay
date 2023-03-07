package datastore

import (
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

var (
	// TODO: standardize integration tests to run with single flag/env var - consolidate with RUN_DB_TESTS
	runIntegrationTests = os.Getenv("RUN_INTEGRATION_TESTS") == "1"
)

func TestNewMemcached(t *testing.T) {
	if !runIntegrationTests {
		t.Skip("Skipping integration tests")
	}

	mem, err := NewMemcached("test")
	require.NoError(t, err, "expected no error on memcache initialization but found %v", err)
	require.NotNil(t, mem, "expected non-nil memcache instance")
}

func TestMemcachedSaveExecutionPayload(t *testing.T) {
	if !runIntegrationTests {
		t.Skip("Skipping integration tests")
	}

	mem, err := NewMemcached("test")
	require.NoError(t, err, "expected no error on memcache initialization but found [%v]", err)
	require.NotNil(t, mem, "expected non-nil memcache instance")

	err = mem.SaveExecutionPayload(0, "0xfoo", "0xbeef", nil)
	require.NoError(t, err, "expected no error on memcache SaveExecutionPayload but found [%v]", err)
}

func TestMemcachedGetExecutionPayload(t *testing.T) {
	if !runIntegrationTests {
		t.Skip("Skipping integration tests")
	}

	mem, err := NewMemcached("test")
	require.NoError(t, err, "expected no error on memcache initialization but found [%v]", err)
	require.NotNil(t, mem, "expected non-nil memcache instance")

	_, err = mem.GetExecutionPayload(0, "0xfoo", "0xbeef")
	require.NoError(t, err, "expected no error on memcache GetExecutionPayload but found [%v]", err)
}
