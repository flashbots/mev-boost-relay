package common

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flashbots/go-boost-utils/types"
)

// BuilderEntry represents a builder that is allowed to send blocks
// Address will be schema://hostname:port
type BuilderEntry struct {
	Address string
	Pubkey  hexutil.Bytes
	URL     *url.URL
}

// NewBuilderEntry creates a new instance based on an input string
// builderURL can be IP@PORT, PUBKEY@IP:PORT, https://IP, etc.
func NewBuilderEntry(builderURL string) (entry *BuilderEntry, err error) {
	if !strings.HasPrefix(builderURL, "http") {
		builderURL = "http://" + builderURL
	}

	url, err := url.Parse(builderURL)
	if err != nil {
		return entry, err
	}

	entry = &BuilderEntry{
		URL:     url,
		Address: entry.URL.Scheme + "://" + entry.URL.Host,
	}
	err = entry.Pubkey.UnmarshalText([]byte(entry.URL.User.Username()))
	return entry, err
}

type EthNetworkDetails struct {
	Name                     string
	GenesisForkVersionHex    string
	GenesisValidatorsRootHex string
	BellatrixForkVersionHex  string
}

var (
	EthNetworkKiln              = "kiln"
	EthNetworkRopsten           = "ropsten"
	EthNetworkSepolia           = "sepolia"
	EthNetworkGoerliShadowFork5 = "goerli-shadow-fork-5"

	GenesisValidatorsRootGoerliShadowFork5 = "0xe45f26d5a29b0ed5a9f62f248b842a30dd7b7fba0b5b104eab271efc04e0cf66"
	GenesisForkVersionGoerliShadowFork5    = "0x13001034"
	BellatrixForkVersionGoerliShadowFork5  = "0x22001034"
)

func NewEthNetworkDetails(networkName string) (ret *EthNetworkDetails, err error) {
	ret = &EthNetworkDetails{
		Name: networkName,
	}
	switch networkName {
	case EthNetworkKiln:
		ret.GenesisForkVersionHex = types.GenesisForkVersionKiln
		ret.GenesisValidatorsRootHex = types.GenesisValidatorsRootKiln
		ret.BellatrixForkVersionHex = types.BellatrixForkVersionKiln
	case EthNetworkRopsten:
		ret.GenesisForkVersionHex = types.GenesisForkVersionRopsten
		ret.GenesisValidatorsRootHex = types.GenesisValidatorsRootRopsten
		ret.BellatrixForkVersionHex = types.BellatrixForkVersionRopsten
	case EthNetworkSepolia:
		ret.GenesisForkVersionHex = types.GenesisForkVersionSepolia
		ret.GenesisValidatorsRootHex = types.GenesisValidatorsRootSepolia
		ret.BellatrixForkVersionHex = types.BellatrixForkVersionSepolia
	case EthNetworkGoerliShadowFork5:
		ret.GenesisForkVersionHex = GenesisForkVersionGoerliShadowFork5
		ret.GenesisValidatorsRootHex = GenesisValidatorsRootGoerliShadowFork5
		ret.BellatrixForkVersionHex = BellatrixForkVersionGoerliShadowFork5
	default:
		return nil, fmt.Errorf("unknown network: %s", networkName)
	}
	return ret, nil
}

type EpochSummary struct {
	Epoch     uint64 `json:"epoch"      db:"epoch"`
	FirstSlot uint64 `json:"slot_first" db:"slot_first"`
	LastSlot  uint64 `json:"slot_last"  db:"slot_last"`

	// Validator stats
	ValidatorsKnownTotal          uint64 `json:"validators_known_total"          db:"validators_known_total"`
	ValidatorRegistrationsTotal   uint64 `json:"validator_registrations_total"   db:"validator_registrations_total"`
	ValidatorRegistrationsRenewed uint64 `json:"validator_registrations_renewed" db:"validator_registrations_renewed"`
	ValidatorRegistrationsNew     uint64 `json:"validator_registrations_new"     db:"validator_registrations_new"`

	// The number of requests are the count of all requests to a specific path, even invalid ones
	NumRegisterValidatorRequests uint64 `json:"num_register_validator_requests" db:"num_register_validator_requests"`
	NumGetHeaderRequests         uint64 `json:"num_get_header_requests"         db:"num_get_header_requests"`
	NumGetPayloadRequests        uint64 `json:"num_get_payload_requests"        db:"num_get_payload_requests"`

	// Responses to successful queries
	NumHeaderSent         uint64 `json:"num_header_sent"          db:"num_header_sent"`
	NumHeaderNoContent    uint64 `json:"num_header_no_content"    db:"num_header_no_content"`
	NumPayloadSent        uint64 `json:"num_payload_sent"         db:"num_payload_sent"`
	NumBuilderBidReceived uint64 `json:"num_builder_bid_received" db:"num_builder_bid_received"`
}
