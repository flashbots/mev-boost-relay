package common

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMakePostRequest(t *testing.T) {
	// Test errors
	var x chan bool
	resp, err := makeRequest(context.Background(), *http.DefaultClient, http.MethodGet, "", x)
	require.Error(t, err)
	require.Nil(t, resp)

	// To satisfy the bodyclose linter.
	if resp != nil {
		resp.Body.Close()
	}
}

func TestGetMevBoostVersionFromUserAgent(t *testing.T) {
	tests := []struct {
		ua      string
		version string
	}{
		{ua: "", version: "-"},
		{ua: "mev-boost", version: "-"},
		{ua: "mev-boost/v1.0.0", version: "v1.0.0"},
		{ua: "mev-boost/v1.0.0 ", version: "v1.0.0"},
		{ua: "mev-boost/v1.0.0 test", version: "v1.0.0"},
	}

	for _, test := range tests {
		t.Run(test.ua, func(t *testing.T) {
			require.Equal(t, test.version, GetMevBoostVersionFromUserAgent(test.ua))
		})
	}
}
