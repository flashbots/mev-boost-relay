package common

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flashbots/go-boost-utils/types"
)

var ErrUnknownNetwork = errors.New("unknown network")

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

	parsedURL, err := url.Parse(builderURL)
	if err != nil {
		return nil, err
	}

	var pubkey hexutil.Bytes
	err = pubkey.UnmarshalText([]byte(entry.URL.User.Username()))
	if err != nil {
		return nil, err
	}

	return &BuilderEntry{
		URL:     parsedURL,
		Address: parsedURL.Scheme + "://" + parsedURL.Host,
		Pubkey:  pubkey,
	}, nil
}

type EthNetworkDetails struct {
	Name                     string
	GenesisForkVersionHex    string
	GenesisValidatorsRootHex string
	BellatrixForkVersionHex  string

	DomainBuilder        types.Domain
	DomainBeaconProposer types.Domain
}

var (
	EthNetworkKiln    = "kiln"
	EthNetworkRopsten = "ropsten"
	EthNetworkSepolia = "sepolia"
	EthNetworkGoerli  = "goerli"
	EthNetworkMainnet = "mainnet"

	GenesisValidatorsRootGoerli = "0x043db0d9a83813551ee2f33450d23797757d430911a9320530ad8a0eabc43efb"
	GenesisForkVersionGoerli    = "0x00001020"
	BellatrixForkVersionGoerli  = "0x02001020"

	GenesisValidatorsRootGoerliShadowFork6 = "0x6985063fa80a61a958ceeac5cf6125991ac297348e42542c85affbe9fb1c7328"
	GenesisForkVersionGoerliShadowFork6    = "0x13001035"
	BellatrixForkVersionGoerliShadowFork6  = "0x22001035"

	// https://github.com/eth-clients/eth2-networks/blob/f3ccbe0cf5798d5cd23e4e6e7119aefa043c0935/shared/mainnet/config.yaml
	GenesisValidatorsRootMainnet = "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
	GenesisForkVersionMainnet    = "0x00000000"
	BellatrixForkVersionMainnet  = "0x02000000"
)

func NewEthNetworkDetails(networkName string) (ret *EthNetworkDetails, err error) {
	var genesisForkVersion string
	var genesisValidatorsRoot string
	var bellatrixForkVersion string
	var domainBuilder types.Domain
	var domainBeaconProposer types.Domain

	switch networkName {
	case EthNetworkKiln:
		genesisForkVersion = types.GenesisForkVersionKiln
		genesisValidatorsRoot = types.GenesisValidatorsRootKiln
		bellatrixForkVersion = types.BellatrixForkVersionKiln
	case EthNetworkRopsten:
		genesisForkVersion = types.GenesisForkVersionRopsten
		genesisValidatorsRoot = types.GenesisValidatorsRootRopsten
		bellatrixForkVersion = types.BellatrixForkVersionRopsten
	case EthNetworkSepolia:
		genesisForkVersion = types.GenesisForkVersionSepolia
		genesisValidatorsRoot = types.GenesisValidatorsRootSepolia
		bellatrixForkVersion = types.BellatrixForkVersionSepolia
	case EthNetworkGoerli:
		genesisForkVersion = GenesisForkVersionGoerli
		genesisValidatorsRoot = GenesisValidatorsRootGoerli
		bellatrixForkVersion = BellatrixForkVersionGoerli
	case EthNetworkMainnet:
		genesisForkVersion = GenesisForkVersionMainnet
		genesisValidatorsRoot = GenesisValidatorsRootMainnet
		bellatrixForkVersion = BellatrixForkVersionMainnet
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnknownNetwork, networkName)
	}

	domainBuilder, err = ComputeDomain(types.DomainTypeAppBuilder, genesisForkVersion, types.Root{}.String())
	if err != nil {
		return nil, err
	}

	domainBeaconProposer, err = ComputeDomain(types.DomainTypeBeaconProposer, bellatrixForkVersion, genesisValidatorsRoot)
	if err != nil {
		return nil, err
	}

	return &EthNetworkDetails{
		Name:                     networkName,
		GenesisForkVersionHex:    genesisForkVersion,
		GenesisValidatorsRootHex: genesisValidatorsRoot,
		BellatrixForkVersionHex:  bellatrixForkVersion,
		DomainBuilder:            domainBuilder,
		DomainBeaconProposer:     domainBeaconProposer,
	}, nil
}

type EpochSummary struct {
	Epoch uint64 `json:"epoch"      db:"epoch"`

	// first and last slots are just derived from the epoch
	SlotFirst uint64 `json:"slot_first" db:"slot_first"`
	SlotLast  uint64 `json:"slot_last"  db:"slot_last"`

	// registered are those that were actually used by the relay (some might be skipped if only one relay and it started in the middle of the epoch)
	SlotFirstProcessed uint64 `json:"slot_first_processed" db:"slot_first_processed"`
	SlotLastProcessed  uint64 `json:"slot_last_processed"  db:"slot_last_processed"`

	// Validator stats
	ValidatorsKnownTotal                     uint64 `json:"validators_known_total"                      db:"validators_known_total"`
	ValidatorRegistrationsTotal              uint64 `json:"validator_registrations_total"               db:"validator_registrations_total"`
	ValidatorRegistrationsSaved              uint64 `json:"validator_registrations_saved"               db:"validator_registrations_saved"`
	ValidatorRegistrationsReceivedUnverified uint64 `json:"validator_registrations_received_unverified" db:"validator_registrations_received_unverified"`

	// The number of requests are the count of all requests to a specific path, even invalid ones
	NumRegisterValidatorRequests uint64 `json:"num_register_validator_requests" db:"num_register_validator_requests"`
	NumGetHeaderRequests         uint64 `json:"num_get_header_requests"         db:"num_get_header_requests"`
	NumGetPayloadRequests        uint64 `json:"num_get_payload_requests"        db:"num_get_payload_requests"`

	// Responses to successful queries
	NumHeaderSentOk       uint64 `json:"num_header_sent_ok"       db:"num_header_sent_ok"`
	NumHeaderSent204      uint64 `json:"num_header_sent_204"      db:"num_header_sent_204"`
	NumPayloadSent        uint64 `json:"num_payload_sent"         db:"num_payload_sent"`
	NumBuilderBidReceived uint64 `json:"num_builder_bid_received" db:"num_builder_bid_received"`

	// Whether all slots were seen
	IsComplete bool `json:"is_complete" db:"is_complete"`
}

type SlotSummary struct {
	Slot   uint64 `json:"slot"   db:"slot"`
	Epoch  uint64 `json:"epoch"  db:"epoch"`
	Missed bool   `json:"missed" db:"missed"`

	// General validator stats
	ValidatorsKnownTotal        uint64 `json:"validators_known_total"                      db:"validators_known_total"`
	ValidatorRegistrationsTotal uint64 `json:"validator_registrations_total"               db:"validator_registrations_total"`

	// Slot proposer details
	ProposerPubkey       string `json:"proposer_pubkey"        db:"proposer_pubkey"`
	ProposerIsRegistered bool   `json:"proposer_is_registered" db:"proposer_is_registered"`

	// The number of requests are the count of all requests to a specific path, even invalid ones
	NumGetHeaderRequests  uint64 `json:"num_get_header_requests"         db:"num_get_header_requests"`
	NumGetPayloadRequests uint64 `json:"num_get_payload_requests"        db:"num_get_payload_requests"`

	// Responses to successful queries
	NumHeaderSentOk       uint64 `json:"num_header_sent_ok"       db:"num_header_sent_ok"`
	NumHeaderSent204      uint64 `json:"num_header_sent_204"      db:"num_header_sent_204"`
	NumPayloadSent        uint64 `json:"num_payload_sent"         db:"num_payload_sent"`
	NumBuilderBidReceived uint64 `json:"num_builder_bid_received" db:"num_builder_bid_received"`
}
