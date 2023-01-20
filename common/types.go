package common

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	apiv1capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/capella"
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

type SignedBeaconBlindedBlock struct {
	Bellatrix *types.SignedBlindedBeaconBlock
	Capella   *apiv1capella.SignedBlindedBeaconBlock
}

func (s *SignedBeaconBlindedBlock) MarshalJSON() ([]byte, error) {
	if s.Capella != nil {
		return json.Marshal(s.Capella)
	}
	return json.Marshal(s.Bellatrix)
}

func (s *SignedBeaconBlindedBlock) Slot() uint64 {
	if s.Capella != nil {
		return uint64(s.Capella.Message.Slot)
	}
	return s.Bellatrix.Message.Slot
}

func (s *SignedBeaconBlindedBlock) BlockHash() string {
	if s.Capella != nil {
		return s.Capella.Message.Body.ExecutionPayloadHeader.BlockHash.String()
	}
	return s.Bellatrix.Message.Body.ExecutionPayloadHeader.BlockHash.String()
}

func (s *SignedBeaconBlindedBlock) BlockNumber() uint64 {
	if s.Capella != nil {
		return s.Capella.Message.Body.ExecutionPayloadHeader.BlockNumber
	}
	return s.Bellatrix.Message.Body.ExecutionPayloadHeader.BlockNumber
}

func (s *SignedBeaconBlindedBlock) ProposerIndex() uint64 {
	if s.Capella != nil {
		return uint64(s.Capella.Message.ProposerIndex)
	}
	return s.Bellatrix.Message.ProposerIndex
}

func (s *SignedBeaconBlindedBlock) Signature() []byte {
	if s.Capella != nil {
		return s.Capella.Signature[:]
	}
	return s.Bellatrix.Signature[:]
}

//nolint:nolintlint,ireturn
func (s *SignedBeaconBlindedBlock) Message() types.HashTreeRoot {
	if s.Capella != nil {
		return s.Capella.Message
	}
	return s.Bellatrix.Message
}

type SignedBeaconBlock struct {
	Bellatrix *types.SignedBeaconBlock
	Capella   *capella.SignedBeaconBlock
}

func (s *SignedBeaconBlock) MarshalJSON() ([]byte, error) {
	if s.Capella != nil {
		return json.Marshal(s.Capella)
	}
	return json.Marshal(s.Bellatrix)
}

func (s *SignedBeaconBlock) Slot() uint64 {
	if s.Capella != nil {
		return uint64(s.Capella.Message.Slot)
	}
	return s.Bellatrix.Message.Slot
}

func (s *SignedBeaconBlock) BlockHash() string {
	if s.Capella != nil {
		return s.Capella.Message.Body.ExecutionPayload.BlockHash.String()
	}
	return s.Bellatrix.Message.Body.ExecutionPayload.BlockHash.String()
}

type ExecutionPayloadHeader struct {
	Bellatrix *types.ExecutionPayloadHeader
	Capella   *capella.ExecutionPayloadHeader
}

type ExecutionPayload struct {
	Bellatrix *types.ExecutionPayload
	Capella   *capella.ExecutionPayload
}

func (e *ExecutionPayload) MarshalJSON() ([]byte, error) {
	if e.Capella != nil {
		return json.Marshal(e.Capella)
	}
	return json.Marshal(e.Bellatrix)
}

func (e *ExecutionPayload) UnmarshalJSON(data []byte) error {
	if e.Capella != nil {
		return json.Unmarshal(data, e.Capella)
	}
	return json.Unmarshal(data, e.Bellatrix)
}

func (e *ExecutionPayload) BlockHash() string {
	if e.Capella != nil {
		return e.Capella.BlockHash.String()
	}
	return e.Bellatrix.BlockHash.String()
}

func (e *ExecutionPayload) ParentHash() string {
	if e.Capella != nil {
		return e.Capella.ParentHash.String()
	}
	return e.Bellatrix.ParentHash.String()
}

func (e *ExecutionPayload) BlockNumber() uint64 {
	if e.Capella != nil {
		return e.Capella.BlockNumber
	}
	return e.Bellatrix.BlockNumber
}

func (e *ExecutionPayload) Timestamp() uint64 {
	if e.Capella != nil {
		return e.Capella.Timestamp
	}
	return e.Bellatrix.Timestamp
}

type VersionedExecutionPayload struct {
	Version          *consensusspec.DataVersion
	ExecutionPayload *ExecutionPayload
}

func (e *ExecutionPayload) TxNum() int {
	if e.Capella != nil {
		return len(e.Capella.Transactions)
	}
	return len(e.Bellatrix.Transactions)
}
