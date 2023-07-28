package common

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	consensusbellatrix "github.com/attestantio/go-eth2-client/spec/bellatrix"
	consensuscapella "github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/flashbots/go-boost-utils/ssz"
	boostTypes "github.com/flashbots/go-boost-utils/types"
	"github.com/holiman/uint256"
)

var (
	ErrUnknownNetwork = errors.New("unknown network")
	ErrEmptyPayload   = errors.New("empty payload")

	EthNetworkRopsten  = "ropsten"
	EthNetworkSepolia  = "sepolia"
	EthNetworkGoerli   = "goerli"
	EthNetworkMainnet  = "mainnet"
	EthNetworkZhejiang = "zhejiang"
	EthNetworkCustom   = "custom"

	CapellaForkVersionRopsten = "0x03001020"
	CapellaForkVersionSepolia = "0x90000072"
	CapellaForkVersionGoerli  = "0x03001020"
	CapellaForkVersionMainnet = "0x03000000"

	// Zhejiang details
	GenesisForkVersionZhejiang    = "0x00000069"
	GenesisValidatorsRootZhejiang = "0x53a92d8f2bb1d85f62d16a156e6ebcd1bcaba652d0900b2c2f387826f3481f6f"
	BellatrixForkVersionZhejiang  = "0x00000071"
	CapellaForkVersionZhejiang    = "0x00000072"

	ForkVersionStringBellatrix = "bellatrix"
	ForkVersionStringCapella   = "capella"
	ForkVersionStringDeneb     = "deneb"
)

type EthNetworkDetails struct {
	Name                     string
	GenesisForkVersionHex    string
	GenesisValidatorsRootHex string
	BellatrixForkVersionHex  string
	CapellaForkVersionHex    string

	DomainBuilder                 phase0.Domain
	DomainBeaconProposerBellatrix phase0.Domain
	DomainBeaconProposerCapella   phase0.Domain
}

func NewEthNetworkDetails(networkName string) (ret *EthNetworkDetails, err error) {
	var genesisForkVersion string
	var genesisValidatorsRoot string
	var bellatrixForkVersion string
	var capellaForkVersion string
	var domainBuilder phase0.Domain
	var domainBeaconProposerBellatrix phase0.Domain
	var domainBeaconProposerCapella phase0.Domain

	switch networkName {
	case EthNetworkRopsten:
		genesisForkVersion = boostTypes.GenesisForkVersionRopsten
		genesisValidatorsRoot = boostTypes.GenesisValidatorsRootRopsten
		bellatrixForkVersion = boostTypes.BellatrixForkVersionRopsten
		capellaForkVersion = CapellaForkVersionRopsten
	case EthNetworkSepolia:
		genesisForkVersion = boostTypes.GenesisForkVersionSepolia
		genesisValidatorsRoot = boostTypes.GenesisValidatorsRootSepolia
		bellatrixForkVersion = boostTypes.BellatrixForkVersionSepolia
		capellaForkVersion = CapellaForkVersionSepolia
	case EthNetworkGoerli:
		genesisForkVersion = boostTypes.GenesisForkVersionGoerli
		genesisValidatorsRoot = boostTypes.GenesisValidatorsRootGoerli
		bellatrixForkVersion = boostTypes.BellatrixForkVersionGoerli
		capellaForkVersion = CapellaForkVersionGoerli
	case EthNetworkMainnet:
		genesisForkVersion = boostTypes.GenesisForkVersionMainnet
		genesisValidatorsRoot = boostTypes.GenesisValidatorsRootMainnet
		bellatrixForkVersion = boostTypes.BellatrixForkVersionMainnet
		capellaForkVersion = CapellaForkVersionMainnet
	case EthNetworkZhejiang:
		genesisForkVersion = GenesisForkVersionZhejiang
		genesisValidatorsRoot = GenesisValidatorsRootZhejiang
		bellatrixForkVersion = BellatrixForkVersionZhejiang
		capellaForkVersion = CapellaForkVersionZhejiang
	case EthNetworkCustom:
		genesisForkVersion = os.Getenv("GENESIS_FORK_VERSION")
		genesisValidatorsRoot = os.Getenv("GENESIS_VALIDATORS_ROOT")
		bellatrixForkVersion = os.Getenv("BELLATRIX_FORK_VERSION")
		capellaForkVersion = os.Getenv("CAPELLA_FORK_VERSION")
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnknownNetwork, networkName)
	}

	domainBuilder, err = ComputeDomain(ssz.DomainTypeAppBuilder, genesisForkVersion, phase0.Root{}.String())
	if err != nil {
		return nil, err
	}

	domainBeaconProposerBellatrix, err = ComputeDomain(ssz.DomainTypeBeaconProposer, bellatrixForkVersion, genesisValidatorsRoot)
	if err != nil {
		return nil, err
	}

	domainBeaconProposerCapella, err = ComputeDomain(ssz.DomainTypeBeaconProposer, capellaForkVersion, genesisValidatorsRoot)
	if err != nil {
		return nil, err
	}

	return &EthNetworkDetails{
		Name:                          networkName,
		GenesisForkVersionHex:         genesisForkVersion,
		GenesisValidatorsRootHex:      genesisValidatorsRoot,
		BellatrixForkVersionHex:       bellatrixForkVersion,
		CapellaForkVersionHex:         capellaForkVersion,
		DomainBuilder:                 domainBuilder,
		DomainBeaconProposerBellatrix: domainBeaconProposerBellatrix,
		DomainBeaconProposerCapella:   domainBeaconProposerCapella,
	}, nil
}

func (e *EthNetworkDetails) String() string {
	return fmt.Sprintf("EthNetworkDetails{Name: %s, GenesisForkVersionHex: %s, GenesisValidatorsRootHex: %s, BellatrixForkVersionHex: %s, CapellaForkVersionHex: %s, DomainBuilder: %x, DomainBeaconProposerBellatrix: %x, DomainBeaconProposerCapella: %x}",
		e.Name, e.GenesisForkVersionHex, e.GenesisValidatorsRootHex, e.BellatrixForkVersionHex, e.CapellaForkVersionHex, e.DomainBuilder, e.DomainBeaconProposerBellatrix, e.DomainBeaconProposerCapella)
}

type PubkeyHex string

func NewPubkeyHex(pk string) PubkeyHex {
	return PubkeyHex(strings.ToLower(pk))
}

func (p PubkeyHex) String() string {
	return string(p)
}

type BuilderGetValidatorsResponseEntry struct {
	Slot           uint64                             `json:"slot,string"`
	ValidatorIndex uint64                             `json:"validator_index,string"`
	Entry          *apiv1.SignedValidatorRegistration `json:"entry"`
}

type BidTraceV2 struct {
	apiv1.BidTrace
	BlockNumber uint64 `db:"block_number" json:"block_number,string"`
	NumTx       uint64 `db:"num_tx"       json:"num_tx,string"`
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

func (b BidTraceV2) MarshalJSON() ([]byte, error) {
	return json.Marshal(&BidTraceV2JSON{
		Slot:                 b.Slot,
		ParentHash:           b.ParentHash.String(),
		BlockHash:            b.BlockHash.String(),
		BuilderPubkey:        b.BuilderPubkey.String(),
		ProposerPubkey:       b.ProposerPubkey.String(),
		ProposerFeeRecipient: b.ProposerFeeRecipient.String(),
		GasLimit:             b.GasLimit,
		GasUsed:              b.GasUsed,
		Value:                b.Value.ToBig().String(),
		NumTx:                b.NumTx,
		BlockNumber:          b.BlockNumber,
	})
}

func (b *BidTraceV2) UnmarshalJSON(data []byte) error {
	params := &struct {
		NumTx       uint64 `json:"num_tx,string"`
		BlockNumber uint64 `json:"block_number,string"`
	}{}
	err := json.Unmarshal(data, params)
	if err != nil {
		return err
	}
	b.NumTx = params.NumTx
	b.BlockNumber = params.BlockNumber

	bidTrace := new(apiv1.BidTrace)
	err = json.Unmarshal(data, bidTrace)
	if err != nil {
		return err
	}
	b.BidTrace = *bidTrace
	return nil
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
	Timestamp            int64 `json:"timestamp,string,omitempty"`
	TimestampMs          int64 `json:"timestamp_ms,string,omitempty"`
	OptimisticSubmission bool  `json:"optimistic_submission"`
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
		"optimistic_submission",
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
		fmt.Sprint(b.OptimisticSubmission),
	}
}

type BlockSubmissionInfo struct {
	BidTrace                   *apiv1.BidTrace
	Slot                       uint64
	BlockHash                  phase0.Hash32
	ParentHash                 phase0.Hash32
	ExecutionPayloadBlockHash  phase0.Hash32
	ExecutionPayloadParentHash phase0.Hash32
	Builder                    phase0.BLSPubKey
	Proposer                   phase0.BLSPubKey
	ProposerFeeRecipient       consensusbellatrix.ExecutionAddress
	GasUsed                    uint64
	GasLimit                   uint64
	Timestamp                  uint64
	BlockNumber                uint64
	Value                      *uint256.Int
	PrevRandao                 phase0.Hash32
	Signature                  phase0.BLSSignature
	Transactions               []consensusbellatrix.Transaction
	Withdrawals                []*consensuscapella.Withdrawal
}
