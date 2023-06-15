package common

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"

	"github.com/attestantio/go-builder-client/api"
	"github.com/attestantio/go-builder-client/api/capella"
	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-builder-client/spec"
	apiv1capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	consensusbellatrix "github.com/attestantio/go-eth2-client/spec/bellatrix"
	consensuscapella "github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"
	boostTypes "github.com/flashbots/go-boost-utils/types"
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

	DomainBuilder                 boostTypes.Domain
	DomainBeaconProposerBellatrix boostTypes.Domain
	DomainBeaconProposerCapella   boostTypes.Domain
}

func NewEthNetworkDetails(networkName string) (ret *EthNetworkDetails, err error) {
	var genesisForkVersion string
	var genesisValidatorsRoot string
	var bellatrixForkVersion string
	var capellaForkVersion string
	var domainBuilder boostTypes.Domain
	var domainBeaconProposerBellatrix boostTypes.Domain
	var domainBeaconProposerCapella boostTypes.Domain

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

	domainBuilder, err = ComputeDomain(boostTypes.DomainTypeAppBuilder, genesisForkVersion, boostTypes.Root{}.String())
	if err != nil {
		return nil, err
	}

	domainBeaconProposerBellatrix, err = ComputeDomain(boostTypes.DomainTypeBeaconProposer, bellatrixForkVersion, genesisValidatorsRoot)
	if err != nil {
		return nil, err
	}

	domainBeaconProposerCapella, err = ComputeDomain(boostTypes.DomainTypeBeaconProposer, capellaForkVersion, genesisValidatorsRoot)
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

type BuilderGetValidatorsResponseEntry struct {
	Slot           uint64                                  `json:"slot,string"`
	ValidatorIndex uint64                                  `json:"validator_index,string"`
	Entry          *boostTypes.SignedValidatorRegistration `json:"entry"`
}

type BidTraceV2 struct {
	apiv1.BidTrace
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

type SignedBlindedBeaconBlock struct {
	Bellatrix *boostTypes.SignedBlindedBeaconBlock
	Capella   *apiv1capella.SignedBlindedBeaconBlock
}

func (s *SignedBlindedBeaconBlock) MarshalJSON() ([]byte, error) {
	if s.Capella != nil {
		return json.Marshal(s.Capella)
	}
	if s.Bellatrix != nil {
		return json.Marshal(s.Bellatrix)
	}
	return nil, ErrEmptyPayload
}

func (s *SignedBlindedBeaconBlock) Slot() uint64 {
	if s.Capella != nil {
		return uint64(s.Capella.Message.Slot)
	}
	if s.Bellatrix != nil {
		return s.Bellatrix.Message.Slot
	}
	return 0
}

func (s *SignedBlindedBeaconBlock) BlockHash() string {
	if s.Capella != nil {
		return s.Capella.Message.Body.ExecutionPayloadHeader.BlockHash.String()
	}
	if s.Bellatrix != nil {
		return s.Bellatrix.Message.Body.ExecutionPayloadHeader.BlockHash.String()
	}
	return ""
}

func (s *SignedBlindedBeaconBlock) BlockNumber() uint64 {
	if s.Capella != nil {
		return s.Capella.Message.Body.ExecutionPayloadHeader.BlockNumber
	}
	if s.Bellatrix != nil {
		return s.Bellatrix.Message.Body.ExecutionPayloadHeader.BlockNumber
	}
	return 0
}

func (s *SignedBlindedBeaconBlock) ProposerIndex() uint64 {
	if s.Capella != nil {
		return uint64(s.Capella.Message.ProposerIndex)
	}
	if s.Bellatrix != nil {
		return s.Bellatrix.Message.ProposerIndex
	}
	return 0
}

func (s *SignedBlindedBeaconBlock) Signature() []byte {
	if s.Capella != nil {
		return s.Capella.Signature[:]
	}
	if s.Bellatrix != nil {
		return s.Bellatrix.Signature[:]
	}
	return nil
}

//nolint:nolintlint,ireturn
func (s *SignedBlindedBeaconBlock) Message() boostTypes.HashTreeRoot {
	if s.Capella != nil {
		return s.Capella.Message
	}
	if s.Bellatrix != nil {
		return s.Bellatrix.Message
	}
	return nil
}

type SignedBeaconBlock struct {
	Bellatrix *boostTypes.SignedBeaconBlock
	Capella   *consensuscapella.SignedBeaconBlock
}

func (s *SignedBeaconBlock) MarshalJSON() ([]byte, error) {
	if s.Capella != nil {
		return json.Marshal(s.Capella)
	}
	if s.Bellatrix != nil {
		return json.Marshal(s.Bellatrix)
	}
	return nil, ErrEmptyPayload
}

func (s *SignedBeaconBlock) Slot() uint64 {
	if s.Capella != nil {
		return uint64(s.Capella.Message.Slot)
	}
	if s.Bellatrix != nil {
		return s.Bellatrix.Message.Slot
	}
	return 0
}

func (s *SignedBeaconBlock) BlockHash() string {
	if s.Capella != nil {
		return s.Capella.Message.Body.ExecutionPayload.BlockHash.String()
	}
	if s.Bellatrix != nil {
		return s.Bellatrix.Message.Body.ExecutionPayload.BlockHash.String()
	}
	return ""
}

type VersionedExecutionPayload struct {
	Bellatrix *boostTypes.GetPayloadResponse
	Capella   *api.VersionedExecutionPayload
}

func (e *VersionedExecutionPayload) MarshalJSON() ([]byte, error) {
	if e.Capella != nil {
		return json.Marshal(e.Capella)
	}
	if e.Bellatrix != nil {
		return json.Marshal(e.Bellatrix)
	}

	return nil, ErrEmptyPayload
}

func (e *VersionedExecutionPayload) UnmarshalJSON(data []byte) error {
	capella := new(api.VersionedExecutionPayload)
	err := json.Unmarshal(data, capella)
	if err == nil && capella.Capella != nil {
		e.Capella = capella
		return nil
	}
	bellatrix := new(boostTypes.GetPayloadResponse)
	err = json.Unmarshal(data, bellatrix)
	if err != nil {
		return err
	}
	e.Bellatrix = bellatrix
	return nil
}

func (e *VersionedExecutionPayload) NumTx() int {
	if e.Capella != nil {
		return len(e.Capella.Capella.Transactions)
	}
	if e.Bellatrix != nil {
		return len(e.Bellatrix.Data.Transactions)
	}
	return 0
}

type BuilderSubmitBlockRequest struct {
	Bellatrix *boostTypes.BuilderSubmitBlockRequest
	Capella   *capella.SubmitBlockRequest
}

func (b *BuilderSubmitBlockRequest) MarshalJSON() ([]byte, error) {
	if b.Capella != nil {
		return json.Marshal(b.Capella)
	}
	if b.Bellatrix != nil {
		return json.Marshal(b.Bellatrix)
	}
	return nil, ErrEmptyPayload
}

func (b *BuilderSubmitBlockRequest) UnmarshalJSON(data []byte) error {
	capella := new(capella.SubmitBlockRequest)
	err := json.Unmarshal(data, capella)
	if err == nil {
		b.Capella = capella
		return nil
	}
	bellatrix := new(boostTypes.BuilderSubmitBlockRequest)
	err = json.Unmarshal(data, bellatrix)
	if err != nil {
		return err
	}
	b.Bellatrix = bellatrix
	return nil
}

func (b *BuilderSubmitBlockRequest) HasExecutionPayload() bool {
	if b.Capella != nil {
		return b.Capella.ExecutionPayload != nil
	}
	if b.Bellatrix != nil {
		return b.Bellatrix.ExecutionPayload != nil
	}
	return false
}

func (b *BuilderSubmitBlockRequest) ExecutionPayloadResponse() (*GetPayloadResponse, error) {
	if b.Bellatrix != nil {
		return &GetPayloadResponse{
			Bellatrix: &boostTypes.GetPayloadResponse{
				Version: boostTypes.VersionString(consensusspec.DataVersionBellatrix.String()),
				Data:    b.Bellatrix.ExecutionPayload,
			},
			Capella: nil,
		}, nil
	}

	if b.Capella != nil {
		return &GetPayloadResponse{
			Capella: &api.VersionedExecutionPayload{
				Version:   consensusspec.DataVersionCapella,
				Capella:   b.Capella.ExecutionPayload,
				Bellatrix: nil,
			},
			Bellatrix: nil,
		}, nil
	}

	return nil, ErrEmptyPayload
}

func (b *BuilderSubmitBlockRequest) Slot() uint64 {
	if b.Capella != nil {
		return b.Capella.Message.Slot
	}
	if b.Bellatrix != nil {
		return b.Bellatrix.Message.Slot
	}
	return 0
}

func (b *BuilderSubmitBlockRequest) BlockHash() string {
	if b.Capella != nil {
		return b.Capella.Message.BlockHash.String()
	}
	if b.Bellatrix != nil {
		return b.Bellatrix.Message.BlockHash.String()
	}
	return ""
}

func (b *BuilderSubmitBlockRequest) ExecutionPayloadBlockHash() string {
	if b.Capella != nil {
		return b.Capella.ExecutionPayload.BlockHash.String()
	}
	if b.Bellatrix != nil {
		return b.Bellatrix.ExecutionPayload.BlockHash.String()
	}
	return ""
}

func (b *BuilderSubmitBlockRequest) BuilderPubkey() phase0.BLSPubKey {
	if b.Capella != nil {
		return b.Capella.Message.BuilderPubkey
	}
	if b.Bellatrix != nil {
		return phase0.BLSPubKey(b.Bellatrix.Message.BuilderPubkey)
	}
	return phase0.BLSPubKey{}
}

func (b *BuilderSubmitBlockRequest) ProposerFeeRecipient() string {
	if b.Capella != nil {
		return b.Capella.Message.ProposerFeeRecipient.String()
	}
	if b.Bellatrix != nil {
		return b.Bellatrix.Message.ProposerFeeRecipient.String()
	}
	return ""
}

func (b *BuilderSubmitBlockRequest) Timestamp() uint64 {
	if b.Capella != nil {
		return b.Capella.ExecutionPayload.Timestamp
	}
	if b.Bellatrix != nil {
		return b.Bellatrix.ExecutionPayload.Timestamp
	}
	return 0
}

func (b *BuilderSubmitBlockRequest) ProposerPubkey() string {
	if b.Capella != nil {
		return b.Capella.Message.ProposerPubkey.String()
	}
	if b.Bellatrix != nil {
		return b.Bellatrix.Message.ProposerPubkey.String()
	}
	return ""
}

func (b *BuilderSubmitBlockRequest) ParentHash() string {
	if b.Capella != nil {
		return b.Capella.Message.ParentHash.String()
	}
	if b.Bellatrix != nil {
		return b.Bellatrix.Message.ParentHash.String()
	}
	return ""
}

func (b *BuilderSubmitBlockRequest) ExecutionPayloadParentHash() string {
	if b.Capella != nil {
		return b.Capella.ExecutionPayload.ParentHash.String()
	}
	if b.Bellatrix != nil {
		return b.Bellatrix.ExecutionPayload.ParentHash.String()
	}
	return ""
}

func (b *BuilderSubmitBlockRequest) Value() *big.Int {
	if b.Capella != nil {
		return b.Capella.Message.Value.ToBig()
	}
	if b.Bellatrix != nil {
		return b.Bellatrix.Message.Value.BigInt()
	}
	return nil
}

func (b *BuilderSubmitBlockRequest) NumTx() int {
	if b.Capella != nil {
		return len(b.Capella.ExecutionPayload.Transactions)
	}
	if b.Bellatrix != nil {
		return len(b.Bellatrix.ExecutionPayload.Transactions)
	}
	return 0
}

func (b *BuilderSubmitBlockRequest) BlockNumber() uint64 {
	if b.Capella != nil {
		return b.Capella.ExecutionPayload.BlockNumber
	}
	if b.Bellatrix != nil {
		return b.Bellatrix.ExecutionPayload.BlockNumber
	}
	return 0
}

func (b *BuilderSubmitBlockRequest) GasUsed() uint64 {
	if b.Capella != nil {
		return b.Capella.ExecutionPayload.GasUsed
	}
	if b.Bellatrix != nil {
		return b.Bellatrix.ExecutionPayload.GasUsed
	}
	return 0
}

func (b *BuilderSubmitBlockRequest) GasLimit() uint64 {
	if b.Capella != nil {
		return b.Capella.ExecutionPayload.GasLimit
	}
	if b.Bellatrix != nil {
		return b.Bellatrix.ExecutionPayload.GasLimit
	}
	return 0
}

func (b *BuilderSubmitBlockRequest) Signature() phase0.BLSSignature {
	if b.Capella != nil {
		return b.Capella.Signature
	}
	if b.Bellatrix != nil {
		return phase0.BLSSignature(b.Bellatrix.Signature)
	}
	return phase0.BLSSignature{}
}

func (b *BuilderSubmitBlockRequest) Random() string {
	if b.Capella != nil {
		return fmt.Sprintf("%#x", b.Capella.ExecutionPayload.PrevRandao)
	}
	if b.Bellatrix != nil {
		return b.Bellatrix.ExecutionPayload.Random.String()
	}
	return ""
}

func (b *BuilderSubmitBlockRequest) Message() *apiv1.BidTrace {
	if b.Capella != nil {
		return b.Capella.Message
	}
	if b.Bellatrix != nil {
		return BoostBidToBidTrace(b.Bellatrix.Message)
	}
	return nil
}

func BoostBidToBidTrace(bidTrace *boostTypes.BidTrace) *apiv1.BidTrace {
	if bidTrace == nil {
		return nil
	}
	return &apiv1.BidTrace{
		BuilderPubkey:        phase0.BLSPubKey(bidTrace.BuilderPubkey),
		Slot:                 bidTrace.Slot,
		ProposerPubkey:       phase0.BLSPubKey(bidTrace.ProposerPubkey),
		ProposerFeeRecipient: consensusbellatrix.ExecutionAddress(bidTrace.ProposerFeeRecipient),
		BlockHash:            phase0.Hash32(bidTrace.BlockHash),
		Value:                U256StrToUint256(bidTrace.Value),
		ParentHash:           phase0.Hash32(bidTrace.ParentHash),
		GasLimit:             bidTrace.GasLimit,
		GasUsed:              bidTrace.GasUsed,
	}
}

type GetPayloadResponse struct {
	Bellatrix *boostTypes.GetPayloadResponse
	Capella   *api.VersionedExecutionPayload
}

func (p *GetPayloadResponse) UnmarshalJSON(data []byte) error {
	capella := new(api.VersionedExecutionPayload)
	err := json.Unmarshal(data, capella)
	if err == nil && capella.Capella != nil {
		p.Capella = capella
		return nil
	}
	bellatrix := new(boostTypes.GetPayloadResponse)
	err = json.Unmarshal(data, bellatrix)
	if err != nil {
		return err
	}
	p.Bellatrix = bellatrix
	return nil
}

func (p *GetPayloadResponse) MarshalJSON() ([]byte, error) {
	if p.Bellatrix != nil {
		return json.Marshal(p.Bellatrix)
	}
	if p.Capella != nil {
		return json.Marshal(p.Capella)
	}
	return nil, ErrEmptyPayload
}

type GetHeaderResponse struct {
	Bellatrix *boostTypes.GetHeaderResponse
	Capella   *spec.VersionedSignedBuilderBid
}

func (p *GetHeaderResponse) UnmarshalJSON(data []byte) error {
	capella := new(spec.VersionedSignedBuilderBid)
	err := json.Unmarshal(data, capella)
	if err == nil && capella.Capella != nil {
		p.Capella = capella
		return nil
	}
	bellatrix := new(boostTypes.GetHeaderResponse)
	err = json.Unmarshal(data, bellatrix)
	if err != nil {
		return err
	}
	p.Bellatrix = bellatrix
	return nil
}

func (p *GetHeaderResponse) MarshalJSON() ([]byte, error) {
	if p.Capella != nil {
		return json.Marshal(p.Capella)
	}
	if p.Bellatrix != nil {
		return json.Marshal(p.Bellatrix)
	}
	return nil, ErrEmptyPayload
}

func (p *GetHeaderResponse) Value() *big.Int {
	if p.Capella != nil {
		return p.Capella.Capella.Message.Value.ToBig()
	}
	if p.Bellatrix != nil {
		return p.Bellatrix.Data.Message.Value.BigInt()
	}
	return nil
}

func (p *GetHeaderResponse) BlockHash() phase0.Hash32 {
	if p.Capella != nil {
		return p.Capella.Capella.Message.Header.BlockHash
	}
	if p.Bellatrix != nil {
		return phase0.Hash32(p.Bellatrix.Data.Message.Header.BlockHash)
	}
	return phase0.Hash32{}
}

func (p *GetHeaderResponse) Empty() bool {
	if p == nil {
		return true
	}
	if p.Capella != nil {
		return p.Capella.Capella == nil || p.Capella.Capella.Message == nil
	}
	if p.Bellatrix != nil {
		return p.Bellatrix.Data == nil || p.Bellatrix.Data.Message == nil
	}
	return true
}

func (b *BuilderSubmitBlockRequest) Withdrawals() []*consensuscapella.Withdrawal {
	if b.Capella != nil {
		return b.Capella.ExecutionPayload.Withdrawals
	}
	return nil
}

// SubmitBlockRequest is the v2 request from the builder to submit a block.
type SubmitBlockRequest struct {
	Message                *apiv1.BidTrace
	ExecutionPayloadHeader *consensuscapella.ExecutionPayloadHeader
	Signature              phase0.BLSSignature              `ssz-size:"96"`
	Transactions           []consensusbellatrix.Transaction `ssz-max:"1048576,1073741824" ssz-size:"?,?"`
	Withdrawals            []*consensuscapella.Withdrawal   `ssz-max:"16"`
}

// MarshalSSZ ssz marshals the SubmitBlockRequest object
func (s *SubmitBlockRequest) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(s)
}

// UnmarshalSSZ ssz unmarshals the SubmitBlockRequest object
func (s *SubmitBlockRequest) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 344 {
		return ssz.ErrSize
	}

	tail := buf
	var o1, o3, o4 uint64

	// Field (0) 'Message'
	if s.Message == nil {
		s.Message = new(apiv1.BidTrace)
	}
	if err = s.Message.UnmarshalSSZ(buf[0:236]); err != nil {
		return err
	}

	// Offset (1) 'ExecutionPayloadHeader'
	if o1 = ssz.ReadOffset(buf[236:240]); o1 > size {
		return ssz.ErrOffset
	}

	if o1 < 344 {
		return ssz.ErrInvalidVariableOffset
	}

	// Field (2) 'Signature'
	copy(s.Signature[:], buf[240:336])

	// Offset (3) 'Transactions'
	if o3 = ssz.ReadOffset(buf[336:340]); o3 > size || o1 > o3 {
		return ssz.ErrOffset
	}

	// Offset (4) 'Withdrawals'
	if o4 = ssz.ReadOffset(buf[340:344]); o4 > size || o3 > o4 {
		return ssz.ErrOffset
	}

	// Field (1) 'ExecutionPayloadHeader'
	{
		buf = tail[o1:o3]
		if s.ExecutionPayloadHeader == nil {
			s.ExecutionPayloadHeader = new(consensuscapella.ExecutionPayloadHeader)
		}
		if err = s.ExecutionPayloadHeader.UnmarshalSSZ(buf); err != nil {
			return err
		}
	}

	// Field (3) 'Transactions'
	{
		buf = tail[o3:o4]
		num, err := ssz.DecodeDynamicLength(buf, 1073741824)
		if err != nil {
			return err
		}
		s.Transactions = make([]consensusbellatrix.Transaction, num)
		err = ssz.UnmarshalDynamic(buf, num, func(indx int, buf []byte) (err error) {
			if len(buf) > 1073741824 {
				return ssz.ErrBytesLength
			}
			if cap(s.Transactions[indx]) == 0 {
				s.Transactions[indx] = consensusbellatrix.Transaction(make([]byte, 0, len(buf)))
			}
			s.Transactions[indx] = append(s.Transactions[indx], buf...)
			return nil
		})
		if err != nil {
			return err
		}
	}

	// Field (4) 'Withdrawals'
	{
		buf = tail[o4:]
		num, err := ssz.DivideInt2(len(buf), 44, 16)
		if err != nil {
			return err
		}
		s.Withdrawals = make([]*consensuscapella.Withdrawal, num)
		for ii := 0; ii < num; ii++ {
			if s.Withdrawals[ii] == nil {
				s.Withdrawals[ii] = new(consensuscapella.Withdrawal)
			}
			if err = s.Withdrawals[ii].UnmarshalSSZ(buf[ii*44 : (ii+1)*44]); err != nil {
				return err
			}
		}
	}
	return err
}

// UnmarshalSSZHeaderOnly ssz unmarshals the first 3 fields of the SubmitBlockRequest object
func (s *SubmitBlockRequest) UnmarshalSSZHeaderOnly(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 344 {
		return ssz.ErrSize
	}

	tail := buf
	var o1, o3 uint64

	// Field (0) 'Message'
	if s.Message == nil {
		s.Message = new(apiv1.BidTrace)
	}
	if err = s.Message.UnmarshalSSZ(buf[0:236]); err != nil {
		return err
	}

	// Offset (1) 'ExecutionPayloadHeader'
	if o1 = ssz.ReadOffset(buf[236:240]); o1 > size {
		return ssz.ErrOffset
	}

	if o1 < 344 {
		return ssz.ErrInvalidVariableOffset
	}

	// Field (2) 'Signature'
	copy(s.Signature[:], buf[240:336])

	// Offset (3) 'Transactions'
	if o3 = ssz.ReadOffset(buf[336:340]); o3 > size || o1 > o3 {
		return ssz.ErrOffset
	}

	// Field (1) 'ExecutionPayloadHeader'
	{
		buf = tail[o1:o3]
		if s.ExecutionPayloadHeader == nil {
			s.ExecutionPayloadHeader = new(consensuscapella.ExecutionPayloadHeader)
		}
		if err = s.ExecutionPayloadHeader.UnmarshalSSZ(buf); err != nil {
			return err
		}
	}
	return err
}

// MarshalSSZTo ssz marshals the SubmitBlockRequest object to a target array
func (s *SubmitBlockRequest) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := int(344)

	// Field (0) 'Message'
	if s.Message == nil {
		s.Message = new(apiv1.BidTrace)
	}
	if dst, err = s.Message.MarshalSSZTo(dst); err != nil {
		return
	}

	// Offset (1) 'ExecutionPayloadHeader'
	dst = ssz.WriteOffset(dst, offset)
	if s.ExecutionPayloadHeader == nil {
		s.ExecutionPayloadHeader = new(consensuscapella.ExecutionPayloadHeader)
	}
	offset += s.ExecutionPayloadHeader.SizeSSZ()

	// Field (2) 'Signature'
	dst = append(dst, s.Signature[:]...)

	// Offset (3) 'Transactions'
	dst = ssz.WriteOffset(dst, offset)
	for ii := 0; ii < len(s.Transactions); ii++ {
		offset += 4
		offset += len(s.Transactions[ii])
	}

	// Offset (4) 'Withdrawals'
	dst = ssz.WriteOffset(dst, offset)

	// Field (1) 'ExecutionPayloadHeader'
	if dst, err = s.ExecutionPayloadHeader.MarshalSSZTo(dst); err != nil {
		return
	}

	// Field (3) 'Transactions'
	if size := len(s.Transactions); size > 1073741824 {
		err = ssz.ErrListTooBigFn("SubmitBlockRequest.Transactions", size, 1073741824)
		return
	}
	{
		offset = 4 * len(s.Transactions)
		for ii := 0; ii < len(s.Transactions); ii++ {
			dst = ssz.WriteOffset(dst, offset)
			offset += len(s.Transactions[ii])
		}
	}
	for ii := 0; ii < len(s.Transactions); ii++ {
		if size := len(s.Transactions[ii]); size > 1073741824 {
			err = ssz.ErrBytesLengthFn("SubmitBlockRequest.Transactions[ii]", size, 1073741824)
			return
		}
		dst = append(dst, s.Transactions[ii]...)
	}

	// Field (4) 'Withdrawals'
	if size := len(s.Withdrawals); size > 16 {
		err = ssz.ErrListTooBigFn("SubmitBlockRequest.Withdrawals", size, 16)
		return
	}
	for ii := 0; ii < len(s.Withdrawals); ii++ {
		if dst, err = s.Withdrawals[ii].MarshalSSZTo(dst); err != nil {
			return
		}
	}
	return dst, nil
}

// SizeSSZ returns the ssz encoded size in bytes for the SubmitBlockRequest object
func (s *SubmitBlockRequest) SizeSSZ() (size int) {
	size = 344

	// Field (1) 'ExecutionPayloadHeader'
	if s.ExecutionPayloadHeader == nil {
		s.ExecutionPayloadHeader = new(consensuscapella.ExecutionPayloadHeader)
	}
	size += s.ExecutionPayloadHeader.SizeSSZ()

	// Field (3) 'Transactions'
	for ii := 0; ii < len(s.Transactions); ii++ {
		size += 4
		size += len(s.Transactions[ii])
	}

	// Field (4) 'Withdrawals'
	size += len(s.Withdrawals) * 44

	return
}
