package common

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
)

func TestBeaconValidators(t *testing.T) {
	r := mux.NewRouter()
	srv := httptest.NewServer(r)
	bc := NewBeaconClientService(srv.URL)

	r.HandleFunc("/eth/v1/beacon/states/head/validators", func(w http.ResponseWriter, _ *http.Request) {
		resp := []byte(`{
  "execution_optimistic": false,
  "data": [
    {
      "index": "1",
      "balance": "1",
      "status": "active_ongoing",
      "validator": {
        "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
        "withdrawal_credentials": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
        "effective_balance": "1",
        "slashed": false,
        "activation_eligibility_epoch": "1",
        "activation_epoch": "1",
        "exit_epoch": "1",
        "withdrawable_epoch": "1"
      }
    }
  ]
}`)
		w.Write(resp)
	})

	_, err := bc.FetchValidators()
	require.NoError(t, err)
	require.Equal(t, uint64(1), bc.NumValidators())
	require.True(t, bc.IsValidator(PubkeyHex("0x93247F2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a")))
	require.Contains(t, bc.validatorSet, PubkeyHex("0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a"))

	entry := bc.validatorSet[PubkeyHex("0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a")]
	require.Equal(t, entry.Validator.Pubkey, "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a")
}
