package beaconclient

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/flashbots/mev-boost-relay/common"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
)

type collectorForTest struct {
	byPubkey map[string]uint64
	resets   int
}

func newCollectorForTest() *collectorForTest {
	return &collectorForTest{byPubkey: make(map[string]uint64)}
}

func (c *collectorForTest) Reset() {
	c.byPubkey = make(map[string]uint64)
	c.resets++
}

func (c *collectorForTest) Add(index uint64, pubkey string) {
	c.byPubkey[pubkey] = index
}

func testPubkey(index int) string { return fmt.Sprintf("0x%096x", index) }

// validatorsJSON renders a response with all the fields a real CL sends, including the
// ones the relay discards.
func validatorsJSON(numValidators int) string {
	var b strings.Builder
	b.WriteString(`{"execution_optimistic":false,"finalized":true,"data":[`)
	for i := range numValidators {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"index":"%d","balance":"32000000000","status":"active_ongoing",`+
			`"validator":{"pubkey":"%s","withdrawal_credentials":"0x00e0f9b1",`+
			`"effective_balance":"32000000000","slashed":false,`+
			`"activation_eligibility_epoch":"1","activation_epoch":"2",`+
			`"exit_epoch":"18446744073709551615","withdrawable_epoch":"18446744073709551615"}}`,
			i, testPubkey(i))
	}
	b.WriteString("]}")
	return b.String()
}

func TestDecodeStateValidators(t *testing.T) {
	t.Run("decodes every entry with the right index", func(t *testing.T) {
		collector := newCollectorForTest()
		require.NoError(t, decodeStateValidators(strings.NewReader(validatorsJSON(3)), collector))

		require.Len(t, collector.byPubkey, 3)
		require.Equal(t, 1, collector.resets)
		for i := range 3 {
			index, found := collector.byPubkey[testPubkey(i)]
			require.True(t, found, "missing validator %d", i)
			require.Equal(t, uint64(i), index) //nolint:gosec
		}
	})

	t.Run("handles an empty validator set", func(t *testing.T) {
		collector := newCollectorForTest()
		require.NoError(t, decodeStateValidators(strings.NewReader(`{"data":[]}`), collector))
		require.Empty(t, collector.byPubkey)
	})

	// The important one: a connection that drops before the validator array closes must
	// be an error, never a silently truncated set that then gets installed as the
	// authoritative validator map. Swept over every possible cut point rather than a
	// few samples, because a single accepted truncation is a missed slot.
	t.Run("rejects every truncation before the array closes", func(t *testing.T) {
		full := validatorsJSON(5)
		closingBracket := strings.LastIndex(full, "]")

		for cut := range closingBracket + 1 {
			collector := newCollectorForTest()
			err := decodeStateValidators(strings.NewReader(full[:cut]), collector)
			require.Error(t, err, "truncation at %d of %d bytes was accepted", cut, len(full))
		}
	})

	// Losing only the outer closing brace is harmless: the array closed, so every
	// validator did arrive. Rejecting it would fail a refresh for no reason.
	t.Run("accepts a response missing only the outer closing brace", func(t *testing.T) {
		full := validatorsJSON(5)
		collector := newCollectorForTest()
		require.NoError(t, decodeStateValidators(strings.NewReader(full[:len(full)-1]), collector))
		require.Len(t, collector.byPubkey, 5)
	})

	t.Run("rejects malformed responses", func(t *testing.T) {
		for name, body := range map[string]string{
			"empty":         ``,
			"no data field": `{"execution_optimistic":false}`,
			"bad entry":     `{"data":[{"index":"not-a-number"}]}`,
		} {
			t.Run(name, func(t *testing.T) {
				collector := newCollectorForTest()
				require.Error(t, decodeStateValidators(strings.NewReader(body), collector))
			})
		}
	})

	// If "data" ever holds something other than an array, that must be a loud error and
	// never an error-free empty validator set - an empty set would be installed as the
	// authoritative map and fail every getPayload. Stock Lighthouse and Prysm cannot
	// produce these today; this guards the case where that stops being true.
	t.Run("rejects data that is not an array", func(t *testing.T) {
		for name, body := range map[string]string{
			"null":             `{"execution_optimistic":false,"data":null}`,
			"number":           `{"execution_optimistic":false,"data":123}`,
			"string":           `{"execution_optimistic":false,"data":"nope"}`,
			"object":           `{"execution_optimistic":false,"data":{}}`,
			"bool":             `{"execution_optimistic":false,"data":true}`,
			"null then fields": `{"data":null,"execution_optimistic":false}`,
		} {
			t.Run(name, func(t *testing.T) {
				collector := newCollectorForTest()
				err := decodeStateValidators(strings.NewReader(body), collector)
				require.Error(t, err, "a non-array data field was accepted as an empty validator set")
			})
		}
	})
}

func TestProdBeaconInstanceStreamStateValidators(t *testing.T) {
	newServer := func(t *testing.T, handler http.HandlerFunc) string {
		t.Helper()
		r := mux.NewRouter()
		srv := httptest.NewServer(r)
		t.Cleanup(srv.Close)
		r.HandleFunc("/eth/v1/beacon/states/{state_id}/validators", handler)
		return srv.URL
	}

	t.Run("streams from the beacon node", func(t *testing.T) {
		url := newServer(t, func(w http.ResponseWriter, req *http.Request) {
			require.Equal(t, "active,pending", req.URL.Query().Get("status"))
			_, err := io.WriteString(w, validatorsJSON(4))
			require.NoError(t, err)
		})

		collector := newCollectorForTest()
		bc := NewProdBeaconInstance(common.TestLog, url, url)
		require.NoError(t, bc.StreamStateValidators("head", collector))
		require.Len(t, collector.byPubkey, 4)
	})

	t.Run("surfaces beacon node errors", func(t *testing.T) {
		url := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, err := io.WriteString(w, `{"code":500,"message":"state not found"}`)
			require.NoError(t, err)
		})

		collector := newCollectorForTest()
		bc := NewProdBeaconInstance(common.TestLog, url, url)
		err := bc.StreamStateValidators("head", collector)
		require.ErrorIs(t, err, ErrHTTPErrorResponse)
		require.ErrorContains(t, err, "state not found")
		require.Empty(t, collector.byPubkey)
	})
}

func TestMultiBeaconClientStreamStateValidators(t *testing.T) {
	// The mocks do not implement the streaming path, so the multi client must say so
	// rather than silently returning an empty validator set.
	t.Run("reports when no instance can stream", func(t *testing.T) {
		bc := NewMultiBeaconClient(common.TestLog, []IBeaconInstance{NewMockBeaconInstance()})

		collector := newCollectorForTest()
		require.ErrorIs(t, bc.StreamStateValidators("head", collector), ErrStreamStateValidatorsUnsupported)
		require.Empty(t, collector.byPubkey)
	})

	t.Run("falls through to the next node, discarding the partial set", func(t *testing.T) {
		r := mux.NewRouter()
		srv := httptest.NewServer(r)
		t.Cleanup(srv.Close)

		// Dies after two validators, leaving the collector holding a partial set.
		r.HandleFunc("/broken/eth/v1/beacon/states/{state_id}/validators", func(w http.ResponseWriter, _ *http.Request) {
			partial := validatorsJSON(3)
			_, err := io.WriteString(w, partial[:len(partial)/2])
			require.NoError(t, err)
		})
		r.HandleFunc("/good/eth/v1/beacon/states/{state_id}/validators", func(w http.ResponseWriter, _ *http.Request) {
			_, err := io.WriteString(w, validatorsJSON(1))
			require.NoError(t, err)
		})

		// beaconInstancesByLeastUsed reverses the order, so the broken node goes first.
		bc := NewMultiBeaconClient(common.TestLog, []IBeaconInstance{
			NewProdBeaconInstance(common.TestLog, srv.URL+"/good", srv.URL+"/good"),
			NewProdBeaconInstance(common.TestLog, srv.URL+"/broken", srv.URL+"/broken"),
		})

		collector := newCollectorForTest()
		require.NoError(t, bc.StreamStateValidators("head", collector))

		require.Len(t, collector.byPubkey, 1)
		require.Contains(t, collector.byPubkey, testPubkey(0))
		require.Equal(t, 2, collector.resets, "each attempt must reset before emitting")
	})
}
