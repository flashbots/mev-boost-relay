package common

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	boostTypes "github.com/flashbots/go-boost-utils/types"
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

func TestU256StrToUint256(t *testing.T) {
	tests := []struct {
		name    string
		u256Str boostTypes.U256Str
		want    string
	}{
		{
			name:    "zero",
			u256Str: boostTypes.U256Str(common.HexToHash("0000000000000000000000000000000000000000000000000000000000000000")),
			want:    "0",
		},
		{
			name:    "one",
			u256Str: boostTypes.U256Str(common.HexToHash("0100000000000000000000000000000000000000000000000000000000000000")),
			want:    "1",
		},
		{
			name:    "bigger value",
			u256Str: boostTypes.U256Str(common.HexToHash("69D8340F00000000000000000000000000000000000000000000000000000000")),
			want:    "255121513",
		},
		{
			name:    "max value",
			u256Str: boostTypes.U256Str(common.HexToHash("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
			want:    "115792089237316195423570985008687907853269984665640564039457584007913129639935",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := U256StrToUint256(test.u256Str)
			require.Equal(t, test.want, fmt.Sprintf("%d", got))
		})
	}
}

func TestGetEnvStrSlice(t *testing.T) {
	testEnvVar := "TESTENV_TestGetEnvStrSlice"
	os.Unsetenv(testEnvVar)
	r := GetEnvStrSlice(testEnvVar, nil)
	require.Len(t, r, 0)

	t.Setenv(testEnvVar, "")
	r = GetEnvStrSlice(testEnvVar, nil)
	require.Len(t, r, 1)
	require.Equal(t, "", r[0])

	t.Setenv(testEnvVar, "str1,str2")
	r = GetEnvStrSlice(testEnvVar, nil)
	require.Len(t, r, 2)
	require.Equal(t, "str1", r[0])
	require.Equal(t, "str2", r[1])
	os.Unsetenv(testEnvVar)
}
