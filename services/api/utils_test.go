package api

import (
	"net/http"
	"strconv"
	"testing"
	"time"

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

func TestComputeGetHeaderDelay(t *testing.T) {
	const (
		slotStartMs = int64(1_700_000_000_000)
		targetMs    = int64(800)
		safetyMs    = int64(5)
		matchedUA   = "some-client-a/1.0.0"
		unmatchedUA = "other-client/2.0.0"
	)
	uas := []string{"some-client-a", "some-client-b"}

	headerWithDeadline := func(date, timeout int64) http.Header {
		return http.Header{
			HeaderDateMilliseconds: []string{strconv.FormatInt(date, 10)},
			HeaderTimeoutMs:        []string{strconv.FormatInt(timeout, 10)},
		}
	}

	for _, tc := range []struct {
		name     string
		ua       string
		nowMs    int64
		header   http.Header
		targetMs int64
		safetyMs int64
		uas      []string
		want     time.Duration
	}{
		{
			name:     "ineligible UA returns no delay",
			ua:       unmatchedUA,
			nowMs:    slotStartMs,
			targetMs: targetMs,
			safetyMs: safetyMs,
			uas:      uas,
			want:     0,
		},
		{
			name:     "target=0 disables delay",
			ua:       matchedUA,
			nowMs:    slotStartMs,
			targetMs: 0,
			safetyMs: safetyMs,
			uas:      uas,
			want:     0,
		},
		{
			name:     "empty UA list returns no delay",
			ua:       matchedUA,
			nowMs:    slotStartMs,
			targetMs: targetMs,
			safetyMs: safetyMs,
			uas:      nil,
			want:     0,
		},
		{
			name:     "matched UA delayed to target minus safety",
			ua:       matchedUA,
			nowMs:    slotStartMs,
			targetMs: targetMs,
			safetyMs: safetyMs,
			uas:      uas,
			want:     time.Duration(targetMs-safetyMs) * time.Millisecond,
		},
		{
			name:     "second substring matches",
			ua:       "some-client-b/0.5.0",
			nowMs:    slotStartMs + 200,
			targetMs: targetMs,
			safetyMs: safetyMs,
			uas:      uas,
			want:     time.Duration(targetMs-200-safetyMs) * time.Millisecond,
		},
		{
			name:     "substring match anywhere in UA",
			ua:       "Go-http-client/1.1 (some-client-a/1.7.0)",
			nowMs:    slotStartMs,
			targetMs: targetMs,
			safetyMs: safetyMs,
			uas:      uas,
			want:     time.Duration(targetMs-safetyMs) * time.Millisecond,
		},
		{
			name:     "empty substring entries are ignored",
			ua:       "anything",
			nowMs:    slotStartMs,
			targetMs: targetMs,
			safetyMs: safetyMs,
			uas:      []string{""},
			want:     0,
		},
		{
			name:     "request past target returns no delay",
			ua:       matchedUA,
			nowMs:    slotStartMs + targetMs,
			targetMs: targetMs,
			safetyMs: safetyMs,
			uas:      uas,
			want:     0,
		},
		{
			name:     "client deadline shorter than target shortens sleep",
			ua:       matchedUA,
			nowMs:    slotStartMs,
			header:   headerWithDeadline(slotStartMs, 500),
			targetMs: targetMs,
			safetyMs: safetyMs,
			uas:      uas,
			want:     time.Duration(500-safetyMs) * time.Millisecond,
		},
		{
			name:     "client deadline longer than target is ignored",
			ua:       matchedUA,
			nowMs:    slotStartMs,
			header:   headerWithDeadline(slotStartMs, 2_000),
			targetMs: targetMs,
			safetyMs: safetyMs,
			uas:      uas,
			want:     time.Duration(targetMs-safetyMs) * time.Millisecond,
		},
		{
			name:     "malformed timing headers fall back to slot cap",
			ua:       matchedUA,
			nowMs:    slotStartMs,
			header:   http.Header{HeaderDateMilliseconds: []string{"oops"}, HeaderTimeoutMs: []string{"500"}},
			targetMs: targetMs,
			safetyMs: safetyMs,
			uas:      uas,
			want:     time.Duration(targetMs-safetyMs) * time.Millisecond,
		},
		{
			name:     "client deadline already passed returns no delay",
			ua:       matchedUA,
			nowMs:    slotStartMs + 100,
			header:   headerWithDeadline(slotStartMs, 50),
			targetMs: targetMs,
			safetyMs: safetyMs,
			uas:      uas,
			want:     0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := computeGetHeaderDelay(tc.ua, slotStartMs, tc.nowMs, tc.header, tc.targetMs, tc.safetyMs, tc.uas)
			require.Equal(t, tc.want, got)
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
			jsonPayload := common.LoadGzippedBytes(t, "./../../testdata/"+tc.fileName)

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
		{
			name:         "submitBlockPayloadElectra_ssz",
			fileName:     "submitBlockPayloadElectra.ssz.gz",
			expectedSlot: 58,
		},
		{
			name:         "submitBlockPayloadFulu_ssz",
			fileName:     "submitBlockPayloadFulu.ssz.gz",
			expectedSlot: 130,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Load the SSZ payload
			sszPayload := common.LoadGzippedBytes(t, "./../../testdata/"+tc.fileName)

			// get the slot from the payload
			slot, err := getSlotFromBuilderSSZPayload(sszPayload)
			require.NoError(t, err)
			require.Equal(t, tc.expectedSlot, slot)
		})
	}
}
