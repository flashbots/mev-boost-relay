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
		genesisForkVersion = types.GenesisForkVersionGoerli
		genesisValidatorsRoot = types.GenesisValidatorsRootGoerli
		bellatrixForkVersion = types.BellatrixForkVersionGoerli
	case EthNetworkMainnet:
		genesisForkVersion = types.GenesisForkVersionMainnet
		genesisValidatorsRoot = types.GenesisValidatorsRootMainnet
		bellatrixForkVersion = types.BellatrixForkVersionMainnet
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

type BidTraceV2 struct {
	types.BidTrace
	BlockNumber uint64 `json:"block_number,string" db:"block_number"`
	NumTx       uint64 `json:"num_tx,string" db:"num_tx"`
}

type BidTraceV2JSON struct {
	Slot                 uint64 `json:"slot,string"`
	ParentHash           string `json:"parent_hash"`
	BlockHash            string `json:"block_hash"`
	BuilderPubkey        string `json:"builder_pubkey"`
	ProposerPubkey       string `json:"proposer_pubkey"`
	ProposerFeeRecipient string `json:"proposer_fee_recipient"`
	GasLimit             uint64 `json:"gas_limit,string"`
	GasUsed              uint64 `json:"gas_used,string"`
	Value                string `json:"value"`
	NumTx                uint64 `json:"num_tx,string"`
	BlockNumber          uint64 `json:"block_number,string"`
}

func (b *BidTraceV2JSON) CSVHeader() []string {
	return []string{
		"slot",
		"parent_hash",
		"block_hash",
		"builder_pubkey",
		"proposer_pubkey",
		"proposer_fee_recipient",
		"gas_limit",
		"gas_used",
		"value",
		"num_tx",
		"block_number",
	}
}

func (b *BidTraceV2JSON) ToCSVRecord() []string {
	return []string{
		fmt.Sprint(b.Slot),
		b.ParentHash,
		b.BlockHash,
		b.BuilderPubkey,
		b.ProposerPubkey,
		b.ProposerFeeRecipient,
		fmt.Sprint(b.GasLimit),
		fmt.Sprint(b.GasUsed),
		b.Value,
		fmt.Sprint(b.NumTx),
		fmt.Sprint(b.BlockNumber),
	}
}

type BidTraceV2WithTimestampJSON struct {
	BidTraceV2JSON
	Timestamp   int64 `json:"timestamp,string,omitempty"`
	TimestampMs int64 `json:"timestamp_ms,string,omitempty"`
}

func (b *BidTraceV2WithTimestampJSON) CSVHeader() []string {
	return []string{
		"slot",
		"parent_hash",
		"block_hash",
		"builder_pubkey",
		"proposer_pubkey",
		"proposer_fee_recipient",
		"gas_limit",
		"gas_used",
		"value",
		"num_tx",
		"block_number",
		"timestamp",
		"timestamp_ms",
	}
}

func (b *BidTraceV2WithTimestampJSON) ToCSVRecord() []string {
	return []string{
		fmt.Sprint(b.Slot),
		b.ParentHash,
		b.BlockHash,
		b.BuilderPubkey,
		b.ProposerPubkey,
		b.ProposerFeeRecipient,
		fmt.Sprint(b.GasLimit),
		fmt.Sprint(b.GasUsed),
		b.Value,
		fmt.Sprint(b.NumTx),
		fmt.Sprint(b.BlockNumber),
		fmt.Sprint(b.Timestamp),
		fmt.Sprint(b.TimestampMs),
	}
}
