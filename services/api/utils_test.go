package api

import (
	"net/http"
	"testing"

	"github.com/flashbots/mev-boost-relay/common"
	"github.com/stretchr/testify/require"
)

func TestGetHeaderContentType(t *testing.T) {
	for _, tc := range []struct {
		header   http.Header
		expected string
	}{
		{
			header:   http.Header{"Content-Type": []string{"application/json"}},
			expected: common.ApplicationJSON,
		},
		{
			header:   http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
			expected: common.ApplicationJSON,
		},
		{
			header:   http.Header{"Content-Type": []string{""}},
			expected: "",
		},
	} {
		t.Run(tc.expected, func(t *testing.T) {
			contentType, _, err := getHeaderContentType(tc.header)
			require.NoError(t, err)
			require.Equal(t, tc.expected, contentType)
		})
	}
}
