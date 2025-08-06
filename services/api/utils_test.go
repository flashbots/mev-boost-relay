package api

import (
	"fmt"
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

func TestGetSlotFromBuilderJSONPayload(t *testing.T) {
	testCases := []struct {
		name         string
		fileName     string
		expectedSlot uint64
	}{
		{
			name:         "submitBlockPayload",
			fileName:     "submitBlockPayload.json.gz",
			expectedSlot: 123,
		},
		{
			name:         "submitBlockPayloadCapella_Goerli_gzipped",
			fileName:     "submitBlockPayloadCapella_Goerli.json.gz",
			expectedSlot: 5552306,
		},
		{
			name:         "submitBlockPayloadDeneb_Goerli",
			fileName:     "submitBlockPayloadDeneb_Goerli.json.gz",
			expectedSlot: 7433483,
		},
		{
			name:         "submitBlockPayloadElectra",
			fileName:     "submitBlockPayloadElectra.json.gz",
			expectedSlot: 58,
		},
		{
			name:         "submitBlockPayloadFulu",
			fileName:     "submitBlockPayloadFulu.json.gz",
			expectedSlot: 130,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jsonPayload := common.LoadGzippedBytes(t, fmt.Sprintf("./../../testdata/%s", tc.fileName))

			// get the slot from the payload
			slot, err := getSlotFromBuilderJSONPayload(jsonPayload)
			require.NoError(t, err)
			require.Equal(t, tc.expectedSlot, slot)
		})
	}
}

func TestGetSlotFromBuilderSSZPayload(t *testing.T) {
	testCases := []struct {
		name         string
		fileName     string
		expectedSlot uint64
	}{
		{
			name:         "submitBlockPayloadCapella_Goerli_ssz",
			fileName:     "submitBlockPayloadCapella_Goerli.ssz.gz",
			expectedSlot: 5552306,
		},
		{
			name:         "submitBlockPayloadDeneb_Goerli_ssz",
			fileName:     "submitBlockPayloadDeneb_Goerli.ssz.gz",
			expectedSlot: 7433483,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Load the SSZ payload
			sszPayload := common.LoadGzippedBytes(t, fmt.Sprintf("./../../testdata/%s", tc.fileName))

			// get the slot from the payload
			slot, err := getSlotFromBuilderSSZPayload(sszPayload)
			require.NoError(t, err)
			require.Equal(t, tc.expectedSlot, slot)
		})
	}
}
