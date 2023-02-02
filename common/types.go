package common

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"

	"github.com/attestantio/go-builder-client/api"
	"github.com/attestantio/go-builder-client/spec"
	apiv1capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common/hexutil"
	boostTypes "github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost-relay/types"
	"github.com/holiman/uint256"
)

var (
	ErrUnknownNetwork = errors.New("unknown network")
	ErrEmptyPayload   = errors.New("empty payload")
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

	DomainBuilder        boostTypes.Domain
	DomainBeaconProposer boostTypes.Domain
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
	var domainBuilder boostTypes.Domain
	var domainBeaconProposer boostTypes.Domain

	switch networkName {
	case EthNetworkKiln:
		genesisForkVersion = boostTypes.GenesisForkVersionKiln
		genesisValidatorsRoot = boostTypes.GenesisValidatorsRootKiln
		bellatrixForkVersion = boostTypes.BellatrixForkVersionKiln
	case EthNetworkRopsten:
		genesisForkVersion = boostTypes.GenesisForkVersionRopsten
		genesisValidatorsRoot = boostTypes.GenesisValidatorsRootRopsten
		bellatrixForkVersion = boostTypes.BellatrixForkVersionRopsten
	case EthNetworkSepolia:
		genesisForkVersion = boostTypes.GenesisForkVersionSepolia
		genesisValidatorsRoot = boostTypes.GenesisValidatorsRootSepolia
		bellatrixForkVersion = boostTypes.BellatrixForkVersionSepolia
	case EthNetworkGoerli:
		genesisForkVersion = boostTypes.GenesisForkVersionGoerli
		genesisValidatorsRoot = boostTypes.GenesisValidatorsRootGoerli
		bellatrixForkVersion = boostTypes.BellatrixForkVersionGoerli
	case EthNetworkMainnet:
		genesisForkVersion = boostTypes.GenesisForkVersionMainnet
		genesisValidatorsRoot = boostTypes.GenesisValidatorsRootMainnet
		bellatrixForkVersion = boostTypes.BellatrixForkVersionMainnet
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnknownNetwork, networkName)
	}

	domainBuilder, err = ComputeDomain(boostTypes.DomainTypeAppBuilder, genesisForkVersion, boostTypes.Root{}.String())
	if err != nil {
		return nil, err
	}

	domainBeaconProposer, err = ComputeDomain(boostTypes.DomainTypeBeaconProposer, bellatrixForkVersion, genesisValidatorsRoot)
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

type SignedBeaconBlindedBlock struct {
	Bellatrix *boostTypes.SignedBlindedBeaconBlock
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
func (s *SignedBeaconBlindedBlock) Message() boostTypes.HashTreeRoot {
	if s.Capella != nil {
		return s.Capella.Message
	}
	return s.Bellatrix.Message
}

type SignedBeaconBlock struct {
	Bellatrix *boostTypes.SignedBeaconBlock
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
	Bellatrix *boostTypes.ExecutionPayloadHeader
	Capella   *capella.ExecutionPayloadHeader
}

type ExecutionPayload struct {
	Bellatrix *boostTypes.ExecutionPayload
	Capella   *capella.ExecutionPayload
}

func (e *ExecutionPayload) MarshalJSON() ([]byte, error) {
	if e.Capella != nil {
		return json.Marshal(e.Capella)
	}
	return json.Marshal(e.Bellatrix)
}

func (e *ExecutionPayload) UnmarshalJSON(data []byte) error {
	capella := new(capella.ExecutionPayload)
	err := json.Unmarshal(data, capella)
	if err == nil {
		e.Capella = capella
		return nil
	}
	bellatrix := new(boostTypes.ExecutionPayload)
	err = json.Unmarshal(data, bellatrix)
	if err != nil {
		return err
	}
	e.Bellatrix = bellatrix
	return nil
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

type BuilderSubmitBlockRequest struct {
	Bellatrix *boostTypes.BuilderSubmitBlockRequest
	Capella   *types.CapellaBuilderSubmitBlockRequest
}

func (b *BuilderSubmitBlockRequest) MarshalJSON() ([]byte, error) {
	if b.Capella != nil {
		return json.Marshal(b.Capella)
	}
	if b.Bellatrix == nil {
		return json.Marshal(b.Bellatrix)
	}
	return nil, ErrEmptyPayload
}

func (b *BuilderSubmitBlockRequest) UnmarshalJSON(data []byte) error {
	capella := new(types.CapellaBuilderSubmitBlockRequest)
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
	if b.Bellatrix == nil {
		return b.Bellatrix.ExecutionPayload != nil
	}
	return false
}

func (b *BuilderSubmitBlockRequest) Slot() uint64 {
	if b.Capella != nil {
		return b.Capella.Message.Slot
	}
	if b.Bellatrix == nil {
		return b.Bellatrix.Message.Slot
	}
	return 0
}

func (b *BuilderSubmitBlockRequest) BlockHash() string {
	if b.Capella != nil {
		return b.Capella.Message.BlockHash.String()
	}
	if b.Bellatrix == nil {
		return b.Bellatrix.Message.BlockHash.String()
	}
	return ""
}

func (b *BuilderSubmitBlockRequest) ExecutionPayloadBlockHash() string {
	if b.Capella != nil {
		return b.Capella.ExecutionPayload.BlockHash.String()
	}
	if b.Bellatrix == nil {
		return b.Bellatrix.ExecutionPayload.BlockHash.String()
	}
	return ""
}

func (b *BuilderSubmitBlockRequest) BuilderPubkey() phase0.BLSPubKey {
	if b.Capella != nil {
		return b.Capella.Message.BuilderPubkey
	}
	if b.Bellatrix == nil {
		return phase0.BLSPubKey(b.Bellatrix.Message.BuilderPubkey)
	}
	return phase0.BLSPubKey{}
}

func (b *BuilderSubmitBlockRequest) ProposerFeeRecipient() string {
	if b.Capella != nil {
		return b.Capella.Message.ProposerFeeRecipient.String()
	}
	if b.Bellatrix == nil {
		return b.Bellatrix.Message.ProposerFeeRecipient.String()
	}
	return ""
}

func (b *BuilderSubmitBlockRequest) Timestamp() uint64 {
	if b.Capella != nil {
		return b.Capella.ExecutionPayload.Timestamp
	}
	if b.Bellatrix == nil {
		return b.Bellatrix.ExecutionPayload.Timestamp
	}
	return 0
}

func (b *BuilderSubmitBlockRequest) ProposerPubkey() string {
	if b.Capella != nil {
		return b.Capella.Message.ProposerPubkey.String()
	}
	if b.Bellatrix == nil {
		return b.Bellatrix.Message.ProposerPubkey.String()
	}
	return ""
}

func (b *BuilderSubmitBlockRequest) ParentHash() string {
	if b.Capella != nil {
		return b.Capella.Message.ParentHash.String()
	}
	if b.Bellatrix == nil {
		return b.Bellatrix.Message.ParentHash.String()
	}
	return ""
}

func (b *BuilderSubmitBlockRequest) ExecutionPayloadParentHash() string {
	if b.Capella != nil {
		return b.Capella.ExecutionPayload.ParentHash.String()
	}
	if b.Bellatrix == nil {
		return b.Bellatrix.ExecutionPayload.ParentHash.String()
	}
	return ""
}

func (b *BuilderSubmitBlockRequest) Value() *big.Int {
	if b.Capella != nil {
		return b.Capella.Message.Value.ToBig()
	}
	if b.Bellatrix == nil {
		return b.Bellatrix.Message.Value.BigInt()
	}
	return nil
}

func (b *BuilderSubmitBlockRequest) TxNum() int {
	if b.Capella != nil {
		return len(b.Capella.ExecutionPayload.Transactions)
	}
	if b.Bellatrix == nil {
		return len(b.Bellatrix.ExecutionPayload.Transactions)
	}
	return 0
}

func (b *BuilderSubmitBlockRequest) BlockNumber() uint64 {
	if b.Capella != nil {
		return b.Capella.ExecutionPayload.BlockNumber
	}
	if b.Bellatrix == nil {
		return b.Bellatrix.ExecutionPayload.BlockNumber
	}
	return 0
}

func (b *BuilderSubmitBlockRequest) GasUsed() uint64 {
	if b.Capella != nil {
		return b.Capella.ExecutionPayload.GasUsed
	}
	if b.Bellatrix == nil {
		return b.Bellatrix.ExecutionPayload.GasUsed
	}
	return 0
}

func (b *BuilderSubmitBlockRequest) GasLimit() uint64 {
	if b.Capella != nil {
		return b.Capella.ExecutionPayload.GasLimit
	}
	if b.Bellatrix == nil {
		return b.Bellatrix.ExecutionPayload.GasLimit
	}
	return 0
}

func (b *BuilderSubmitBlockRequest) Signature() phase0.BLSSignature {
	if b.Capella != nil {
		return b.Capella.Signature
	}
	if b.Bellatrix == nil {
		return phase0.BLSSignature(b.Bellatrix.Signature)
	}
	return phase0.BLSSignature{}
}

func (b *BuilderSubmitBlockRequest) Random() string {
	if b.Capella != nil {
		return fmt.Sprintf("%#x", b.Capella.ExecutionPayload.PrevRandao)
	}
	if b.Bellatrix == nil {
		return b.Bellatrix.ExecutionPayload.Random.String()
	}
	return ""
}

func (b *BuilderSubmitBlockRequest) Message() *boostTypes.BidTrace {
	if b.Capella != nil {
		return BidTraceToBoostBid(b.Capella.Message)
	}
	if b.Bellatrix == nil {
		return b.Bellatrix.Message
	}
	return nil
}

func BidTraceToBoostBid(bidTrace *types.BidTrace) *boostTypes.BidTrace {
	return &boostTypes.BidTrace{
		BuilderPubkey:        boostTypes.PublicKey(bidTrace.BuilderPubkey),
		Slot:                 bidTrace.Slot,
		ProposerPubkey:       boostTypes.PublicKey(bidTrace.ProposerPubkey),
		ProposerFeeRecipient: boostTypes.Address(bidTrace.ProposerFeeRecipient),
		BlockHash:            boostTypes.Hash(bidTrace.BlockHash),
		Value:                boostTypes.IntToU256(bidTrace.Value.Uint64()),
		ParentHash:           boostTypes.Hash(bidTrace.ParentHash),
		GasLimit:             bidTrace.GasLimit,
		GasUsed:              bidTrace.GasUsed,
	}
}

func BoostBidToBidTrace(bidTrace *boostTypes.BidTrace) *types.BidTrace {
	return &types.BidTrace{
		BuilderPubkey:        phase0.BLSPubKey(bidTrace.BuilderPubkey),
		Slot:                 bidTrace.Slot,
		ProposerPubkey:       phase0.BLSPubKey(bidTrace.ProposerPubkey),
		ProposerFeeRecipient: bellatrix.ExecutionAddress(bidTrace.ProposerFeeRecipient),
		BlockHash:            phase0.Hash32(bidTrace.BlockHash),
		Value:                *uint256.NewInt(bidTrace.Value.BigInt().Uint64()),
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
	if err == nil {
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
	if err == nil {
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
