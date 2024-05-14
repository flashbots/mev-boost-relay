package common

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	builderApiV1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"
	boostSsz "github.com/flashbots/go-boost-utils/ssz"
)

var (
	ErrUnknownNetwork      = errors.New("unknown network")
	ErrEmptyPayload        = errors.New("empty payload")
	ErrEmptyPayloadHeader  = errors.New("empty payload header")
	ErrEmptyPayloadMessage = errors.New("empty payload message")
	ErrVersionNotSupported = errors.New("version is not supported")

	EthNetworkHolesky = "holesky"
	EthNetworkSepolia = "sepolia"
	EthNetworkGoerli  = "goerli"
	EthNetworkMainnet = "mainnet"
	EthNetworkCustom  = "custom"

	GenesisForkVersionHolesky = "0x01017000"
	GenesisForkVersionSepolia = "0x90000069"
	GenesisForkVersionGoerli  = "0x00001020"
	GenesisForkVersionMainnet = "0x00000000"

	GenesisValidatorsRootHolesky = "0x9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1"
	GenesisValidatorsRootSepolia = "0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078"
	GenesisValidatorsRootGoerli  = "0x043db0d9a83813551ee2f33450d23797757d430911a9320530ad8a0eabc43efb"
	GenesisValidatorsRootMainnet = "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"

	BellatrixForkVersionHolesky = "0x03017000"
	BellatrixForkVersionSepolia = "0x90000071"
	BellatrixForkVersionGoerli  = "0x02001020"
	BellatrixForkVersionMainnet = "0x02000000"

	CapellaForkVersionHolesky = "0x04017000"
	CapellaForkVersionSepolia = "0x90000072"
	CapellaForkVersionGoerli  = "0x03001020"
	CapellaForkVersionMainnet = "0x03000000"

	DenebForkVersionHolesky = "0x05017000"
	DenebForkVersionSepolia = "0x90000073"
	DenebForkVersionGoerli  = "0x04001020"
	DenebForkVersionMainnet = "0x04000000"

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
	DenebForkVersionHex      string

	DomainBuilder                 phase0.Domain
	DomainBeaconProposerBellatrix phase0.Domain
	DomainBeaconProposerCapella   phase0.Domain
	DomainBeaconProposerDeneb     phase0.Domain
}

func NewEthNetworkDetails(networkName string) (ret *EthNetworkDetails, err error) {
	var genesisForkVersion string
	var genesisValidatorsRoot string
	var bellatrixForkVersion string
	var capellaForkVersion string
	var denebForkVersion string
	var domainBuilder phase0.Domain
	var domainBeaconProposerBellatrix phase0.Domain
	var domainBeaconProposerCapella phase0.Domain
	var domainBeaconProposerDeneb phase0.Domain

	switch networkName {
	case EthNetworkHolesky:
		genesisForkVersion = GenesisForkVersionHolesky
		genesisValidatorsRoot = GenesisValidatorsRootHolesky
		bellatrixForkVersion = BellatrixForkVersionHolesky
		capellaForkVersion = CapellaForkVersionHolesky
		denebForkVersion = DenebForkVersionHolesky
	case EthNetworkSepolia:
		genesisForkVersion = GenesisForkVersionSepolia
		genesisValidatorsRoot = GenesisValidatorsRootSepolia
		bellatrixForkVersion = BellatrixForkVersionSepolia
		capellaForkVersion = CapellaForkVersionSepolia
		denebForkVersion = DenebForkVersionSepolia
	case EthNetworkGoerli:
		genesisForkVersion = GenesisForkVersionGoerli
		genesisValidatorsRoot = GenesisValidatorsRootGoerli
		bellatrixForkVersion = BellatrixForkVersionGoerli
		capellaForkVersion = CapellaForkVersionGoerli
		denebForkVersion = DenebForkVersionGoerli
	case EthNetworkMainnet:
		genesisForkVersion = GenesisForkVersionMainnet
		genesisValidatorsRoot = GenesisValidatorsRootMainnet
		bellatrixForkVersion = BellatrixForkVersionMainnet
		capellaForkVersion = CapellaForkVersionMainnet
		denebForkVersion = DenebForkVersionMainnet
	case EthNetworkCustom:
		genesisForkVersion = os.Getenv("GENESIS_FORK_VERSION")
		genesisValidatorsRoot = os.Getenv("GENESIS_VALIDATORS_ROOT")
		bellatrixForkVersion = os.Getenv("BELLATRIX_FORK_VERSION")
		capellaForkVersion = os.Getenv("CAPELLA_FORK_VERSION")
		denebForkVersion = os.Getenv("DENEB_FORK_VERSION")
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnknownNetwork, networkName)
	}

	domainBuilder, err = ComputeDomain(boostSsz.DomainTypeAppBuilder, genesisForkVersion, phase0.Root{}.String())
	if err != nil {
		return nil, err
	}

	domainBeaconProposerBellatrix, err = ComputeDomain(boostSsz.DomainTypeBeaconProposer, bellatrixForkVersion, genesisValidatorsRoot)
	if err != nil {
		return nil, err
	}

	domainBeaconProposerCapella, err = ComputeDomain(boostSsz.DomainTypeBeaconProposer, capellaForkVersion, genesisValidatorsRoot)
	if err != nil {
		return nil, err
	}

	domainBeaconProposerDeneb, err = ComputeDomain(boostSsz.DomainTypeBeaconProposer, denebForkVersion, genesisValidatorsRoot)
	if err != nil {
		return nil, err
	}

	return &EthNetworkDetails{
		Name:                          networkName,
		GenesisForkVersionHex:         genesisForkVersion,
		GenesisValidatorsRootHex:      genesisValidatorsRoot,
		BellatrixForkVersionHex:       bellatrixForkVersion,
		CapellaForkVersionHex:         capellaForkVersion,
		DenebForkVersionHex:           denebForkVersion,
		DomainBuilder:                 domainBuilder,
		DomainBeaconProposerBellatrix: domainBeaconProposerBellatrix,
		DomainBeaconProposerCapella:   domainBeaconProposerCapella,
		DomainBeaconProposerDeneb:     domainBeaconProposerDeneb,
	}, nil
}

func (e *EthNetworkDetails) String() string {
	return fmt.Sprintf(
		`EthNetworkDetails{
	Name: %s, 
	GenesisForkVersionHex: %s, 
	GenesisValidatorsRootHex: %s,
	BellatrixForkVersionHex: %s, 
	CapellaForkVersionHex: %s, 
	DenebForkVersionHex: %s,
	DomainBuilder: %x, 
	DomainBeaconProposerBellatrix: %x, 
	DomainBeaconProposerCapella: %x, 
	DomainBeaconProposerDeneb: %x
}`,
		e.Name,
		e.GenesisForkVersionHex,
		e.GenesisValidatorsRootHex,
		e.BellatrixForkVersionHex,
		e.CapellaForkVersionHex,
		e.DenebForkVersionHex,
		e.DomainBuilder,
		e.DomainBeaconProposerBellatrix,
		e.DomainBeaconProposerCapella,
		e.DomainBeaconProposerDeneb)
}

type PubkeyHex string

func NewPubkeyHex(pk string) PubkeyHex {
	return PubkeyHex(strings.ToLower(pk))
}

func (p PubkeyHex) String() string {
	return string(p)
}

type BuilderGetValidatorsResponseEntry struct {
	Slot           uint64                                    `json:"slot,string"`
	ValidatorIndex uint64                                    `json:"validator_index,string"`
	Entry          *builderApiV1.SignedValidatorRegistration `json:"entry"`
}

type BidTraceV2 struct {
	builderApiV1.BidTrace
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

	bidTrace := new(builderApiV1.BidTrace)
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
		strconv.FormatUint(b.Slot, 10),
		b.ParentHash,
		b.BlockHash,
		b.BuilderPubkey,
		b.ProposerPubkey,
		b.ProposerFeeRecipient,
		strconv.FormatUint(b.GasLimit, 10),
		strconv.FormatUint(b.GasUsed, 10),
		b.Value,
		strconv.FormatUint(b.NumTx, 10),
		strconv.FormatUint(b.BlockNumber, 10),
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
		strconv.FormatUint(b.Slot, 10),
		b.ParentHash,
		b.BlockHash,
		b.BuilderPubkey,
		b.ProposerPubkey,
		b.ProposerFeeRecipient,
		strconv.FormatUint(b.GasLimit, 10),
		strconv.FormatUint(b.GasUsed, 10),
		b.Value,
		strconv.FormatUint(b.NumTx, 10),
		strconv.FormatUint(b.BlockNumber, 10),
		strconv.FormatInt(b.Timestamp, 10),
		strconv.FormatInt(b.TimestampMs, 10),
		strconv.FormatBool(b.OptimisticSubmission),
	}
}

type BidTraceV2WithBlobFields struct {
	builderApiV1.BidTrace
	BlockNumber   uint64 `db:"block_number"    json:"block_number,string"`
	NumTx         uint64 `db:"num_tx"          json:"num_tx,string"`
	NumBlobs      uint64 `db:"num_blobs"       json:"num_blobs,string"`
	BlobGasUsed   uint64 `db:"blob_gas_used"   json:"blob_gas_used,string"`
	ExcessBlobGas uint64 `db:"excess_blob_gas" json:"excess_blob_gas,string"`
}

type BidTraceV2WithBlobFieldsJSON struct {
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
	NumBlobs             uint64 `json:"num_blobs,string"`
	BlobGasUsed          uint64 `json:"blob_gas_used,string"`
	ExcessBlobGas        uint64 `json:"excess_blob_gas,string"`
}

func (b BidTraceV2WithBlobFields) MarshalJSON() ([]byte, error) {
	return json.Marshal(&BidTraceV2WithBlobFieldsJSON{
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
		NumBlobs:             b.NumBlobs,
		BlobGasUsed:          b.BlobGasUsed,
		ExcessBlobGas:        b.ExcessBlobGas,
	})
}

func (b *BidTraceV2WithBlobFields) UnmarshalJSON(data []byte) error {
	params := &struct {
		NumTx         uint64 `json:"num_tx,string"`
		BlockNumber   uint64 `json:"block_number,string"`
		NumBlobs      uint64 `json:"num_blobs,string"`
		BlobGasUsed   uint64 `json:"blob_gas_used,string"`
		ExcessBlobGas uint64 `json:"excess_blob_gas,string"`
	}{}
	err := json.Unmarshal(data, params)
	if err != nil {
		return err
	}
	b.NumTx = params.NumTx
	b.BlockNumber = params.BlockNumber
	b.NumBlobs = params.NumBlobs
	b.BlobGasUsed = params.BlobGasUsed
	b.ExcessBlobGas = params.ExcessBlobGas

	bidTrace := new(builderApiV1.BidTrace)
	err = json.Unmarshal(data, bidTrace)
	if err != nil {
		return err
	}
	b.BidTrace = *bidTrace
	return nil
}

type BlockSubmissionInfo struct {
	BidTrace                   *builderApiV1.BidTrace
	ExecutionPayloadBlockHash  phase0.Hash32
	ExecutionPayloadParentHash phase0.Hash32
	GasUsed                    uint64
	GasLimit                   uint64
	Timestamp                  uint64
	BlockNumber                uint64
	PrevRandao                 phase0.Hash32
	Signature                  phase0.BLSSignature
	Transactions               []bellatrix.Transaction
	Withdrawals                []*capella.Withdrawal
	Blobs                      []deneb.Blob
	BlobGasUsed                uint64
	ExcessBlobGas              uint64
}

type HeaderSubmissionInfo struct {
	BidTrace         *builderApiV1.BidTrace
	Signature        phase0.BLSSignature
	Timestamp        uint64
	PrevRandao       phase0.Hash32
	TransactionsRoot phase0.Root
	WithdrawalsRoot  phase0.Root
	GasUsed          uint64
	GasLimit         uint64
	BlockNumber      uint64
}

// VersionedSubmitHeaderOptimistic is a versioned signed header to construct the builder bid.
type VersionedSubmitHeaderOptimistic struct {
	Version spec.DataVersion
	Deneb   *DenebSubmitHeaderOptimistic
}

func (h *VersionedSubmitHeaderOptimistic) MarshalSSZ() ([]byte, error) {
	switch h.Version { //nolint:exhaustive
	case spec.DataVersionDeneb:
		return h.Deneb.MarshalSSZ()
	default:
		return nil, fmt.Errorf("%w: %s", ErrVersionNotSupported, h.Version)
	}
}

func (h *VersionedSubmitHeaderOptimistic) UnmarshalSSZ(data []byte) error {
	var err error
	denebHeader := &DenebSubmitHeaderOptimistic{}
	if err = denebHeader.UnmarshalSSZ(data); err == nil {
		h.Version = spec.DataVersionDeneb
		h.Deneb = denebHeader
		return nil
	}
	return err
}

func (h *VersionedSubmitHeaderOptimistic) MarshalJSON() ([]byte, error) {
	switch h.Version { //nolint:exhaustive
	case spec.DataVersionDeneb:
		return json.Marshal(h.Deneb)
	default:
		return nil, fmt.Errorf("%w: %s", ErrVersionNotSupported, h.Version)
	}
}

func (h *VersionedSubmitHeaderOptimistic) UnmarshalJSON(data []byte) error {
	var err error
	denebHeader := &DenebSubmitHeaderOptimistic{}
	if err = json.Unmarshal(data, denebHeader); err == nil {
		h.Version = spec.DataVersionDeneb
		h.Deneb = denebHeader
		return nil
	}
	return err
}

func (h *VersionedSubmitHeaderOptimistic) BidTrace() (*builderApiV1.BidTrace, error) {
	switch h.Version { //nolint:exhaustive
	case spec.DataVersionDeneb:
		if h.Deneb == nil {
			return nil, ErrEmptyPayload
		}
		if h.Deneb.Message == nil {
			return nil, ErrEmptyPayloadMessage
		}
		return h.Deneb.Message, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrVersionNotSupported, h.Version)
	}
}

func (h *VersionedSubmitHeaderOptimistic) ExecutionPayloadBlockHash() (phase0.Hash32, error) {
	switch h.Version { //nolint:exhaustive
	case spec.DataVersionDeneb:
		if h.Deneb == nil {
			return phase0.Hash32{}, ErrEmptyPayload
		}
		if h.Deneb.ExecutionPayloadHeader == nil {
			return phase0.Hash32{}, ErrEmptyPayloadHeader
		}
		return h.Deneb.ExecutionPayloadHeader.BlockHash, nil
	default:
		return phase0.Hash32{}, fmt.Errorf("%w: %s", ErrVersionNotSupported, h.Version)
	}
}

func (h *VersionedSubmitHeaderOptimistic) Signature() (phase0.BLSSignature, error) {
	switch h.Version { //nolint:exhaustive
	case spec.DataVersionDeneb:
		if h.Deneb == nil {
			return phase0.BLSSignature{}, ErrEmptyPayload
		}
		return h.Deneb.Signature, nil
	default:
		return phase0.BLSSignature{}, fmt.Errorf("%w: %s", ErrVersionNotSupported, h.Version)
	}
}

func (h *VersionedSubmitHeaderOptimistic) Timestamp() (uint64, error) {
	switch h.Version { //nolint:exhaustive
	case spec.DataVersionDeneb:
		if h.Deneb == nil {
			return 0, ErrEmptyPayload
		}
		if h.Deneb.ExecutionPayloadHeader == nil {
			return 0, ErrEmptyPayloadHeader
		}
		return h.Deneb.ExecutionPayloadHeader.Timestamp, nil
	default:
		return 0, fmt.Errorf("%w: %s", ErrVersionNotSupported, h.Version)
	}
}

func (h *VersionedSubmitHeaderOptimistic) PrevRandao() (phase0.Hash32, error) {
	switch h.Version { //nolint:exhaustive
	case spec.DataVersionDeneb:
		if h.Deneb == nil {
			return phase0.Hash32{}, ErrEmptyPayload
		}
		if h.Deneb.ExecutionPayloadHeader == nil {
			return phase0.Hash32{}, ErrEmptyPayloadHeader
		}
		return h.Deneb.ExecutionPayloadHeader.PrevRandao, nil
	default:
		return phase0.Hash32{}, fmt.Errorf("%w: %s", ErrVersionNotSupported, h.Version)
	}
}

func (h *VersionedSubmitHeaderOptimistic) TransactionsRoot() (phase0.Root, error) {
	switch h.Version { //nolint:exhaustive
	case spec.DataVersionDeneb:
		if h.Deneb == nil {
			return phase0.Root{}, ErrEmptyPayload
		}
		if h.Deneb.ExecutionPayloadHeader == nil {
			return phase0.Root{}, ErrEmptyPayloadHeader
		}
		return h.Deneb.ExecutionPayloadHeader.TransactionsRoot, nil
	default:
		return phase0.Root{}, fmt.Errorf("%w: %s", ErrVersionNotSupported, h.Version)
	}
}

func (h *VersionedSubmitHeaderOptimistic) WithdrawalsRoot() (phase0.Root, error) {
	switch h.Version { //nolint:exhaustive
	case spec.DataVersionDeneb:
		if h.Deneb == nil {
			return phase0.Root{}, ErrEmptyPayload
		}
		if h.Deneb.ExecutionPayloadHeader == nil {
			return phase0.Root{}, ErrEmptyPayloadHeader
		}
		return h.Deneb.ExecutionPayloadHeader.WithdrawalsRoot, nil
	default:
		return phase0.Root{}, fmt.Errorf("%w: %s", ErrVersionNotSupported, h.Version)
	}
}

func (h *VersionedSubmitHeaderOptimistic) GasUsed() (uint64, error) {
	switch h.Version { //nolint:exhaustive
	case spec.DataVersionDeneb:
		if h.Deneb == nil {
			return 0, ErrEmptyPayload
		}
		if h.Deneb.ExecutionPayloadHeader == nil {
			return 0, ErrEmptyPayloadHeader
		}
		return h.Deneb.ExecutionPayloadHeader.GasUsed, nil
	default:
		return 0, fmt.Errorf("%w: %s", ErrVersionNotSupported, h.Version)
	}
}

func (h *VersionedSubmitHeaderOptimistic) GasLimit() (uint64, error) {
	switch h.Version { //nolint:exhaustive
	case spec.DataVersionDeneb:
		if h.Deneb == nil {
			return 0, ErrEmptyPayload
		}
		if h.Deneb.ExecutionPayloadHeader == nil {
			return 0, ErrEmptyPayloadHeader
		}
		return h.Deneb.ExecutionPayloadHeader.GasLimit, nil
	default:
		return 0, fmt.Errorf("%w: %s", ErrVersionNotSupported, h.Version)
	}
}

func (h *VersionedSubmitHeaderOptimistic) BlockNumber() (uint64, error) {
	switch h.Version { //nolint:exhaustive
	case spec.DataVersionDeneb:
		if h.Deneb == nil {
			return 0, ErrEmptyPayload
		}
		if h.Deneb.ExecutionPayloadHeader == nil {
			return 0, ErrEmptyPayloadHeader
		}
		return h.Deneb.ExecutionPayloadHeader.BlockNumber, nil
	default:
		return 0, fmt.Errorf("%w: %s", ErrVersionNotSupported, h.Version)
	}
}

/*
DenebSubmitHeaderOptimistic is request from the builder to submit a Deneb header. At minimum
without blobs, it is 956 bytes. With the current maximum of 6 blobs this adds another 288
bytes for a total of 1244 bytes.

Layout:
[000-236) = Message   				  (236 bytes)
[236-240) = offset1   				  (  4 bytes) ExecutionPayloadHeader
[240-244) = offset2   				  (  4 bytes) BlobKZGCommitments
[244-340) = Signature 				  ( 96 bytes)
[340-956) = EPH       				  (616 bytes)
[956-?)   = len(KZGCommitments) * 48  ( variable)
*/
type DenebSubmitHeaderOptimistic struct {
	Message                *builderApiV1.BidTrace        `json:"message"`
	ExecutionPayloadHeader *deneb.ExecutionPayloadHeader `json:"header"`
	BlobKZGCommitments     []deneb.KZGCommitment         `json:"blob_kzg_commitments" ssz-max:"4096" ssz-size:"?,48"`
	Signature              phase0.BLSSignature           `json:"signature"            ssz-size:"96"`
}

// MarshalSSZ ssz marshals the DenebSubmitHeaderOptimistic object
func (d *DenebSubmitHeaderOptimistic) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(d)
}

// MarshalSSZTo ssz marshals the DenebSubmitHeaderOptimistic object to a target array
func (d *DenebSubmitHeaderOptimistic) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := int(340)

	// Field (0) 'Message'
	if d.Message == nil {
		d.Message = new(builderApiV1.BidTrace)
	}
	if dst, err = d.Message.MarshalSSZTo(dst); err != nil {
		return nil, err
	}

	// Offset (1) 'ExecutionPayloadHeader'
	dst = ssz.WriteOffset(dst, offset)
	if d.ExecutionPayloadHeader == nil {
		d.ExecutionPayloadHeader = new(deneb.ExecutionPayloadHeader)
	}
	offset += d.ExecutionPayloadHeader.SizeSSZ()

	// Offset (2) 'BlobKZGCommitments'
	dst = ssz.WriteOffset(dst, offset)

	// Field (3) 'Signature'
	dst = append(dst, d.Signature[:]...)

	// Field (1) 'ExecutionPayloadHeader'
	if dst, err = d.ExecutionPayloadHeader.MarshalSSZTo(dst); err != nil {
		return nil, err
	}

	// Field (2) 'BlobKZGCommitments'
	if size := len(d.BlobKZGCommitments); size > 4096 {
		err = ssz.ErrListTooBigFn("DenebSubmitHeaderOptimistic.BlobKZGCommitments", size, 4096)
		return nil, err
	}
	for ii := 0; ii < len(d.BlobKZGCommitments); ii++ {
		dst = append(dst, d.BlobKZGCommitments[ii][:]...)
	}

	return dst, err
}

// UnmarshalSSZ ssz unmarshals the DenebSubmitHeaderOptimistic object
func (d *DenebSubmitHeaderOptimistic) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 340 {
		return ssz.ErrSize
	}

	tail := buf
	var o1, o2 uint64

	// Field (0) 'Message'
	if d.Message == nil {
		d.Message = new(builderApiV1.BidTrace)
	}
	if err = d.Message.UnmarshalSSZ(buf[0:236]); err != nil {
		return err
	}

	// Offset (1) 'ExecutionPayloadHeader'
	if o1 = ssz.ReadOffset(buf[236:240]); o1 > size {
		return ssz.ErrOffset
	}

	if o1 < 340 {
		return ssz.ErrInvalidVariableOffset
	}

	// Offset (2) 'BlobKZGCommitments'
	if o2 = ssz.ReadOffset(buf[240:244]); o2 > size || o1 > o2 {
		return ssz.ErrOffset
	}

	// Field (3) 'Signature'
	copy(d.Signature[:], buf[244:340])

	// Field (1) 'ExecutionPayloadHeader'
	{
		buf = tail[o1:o2]
		if d.ExecutionPayloadHeader == nil {
			d.ExecutionPayloadHeader = new(deneb.ExecutionPayloadHeader)
		}
		if err = d.ExecutionPayloadHeader.UnmarshalSSZ(buf); err != nil {
			return err
		}
	}

	// Field (2) 'BlobKZGCommitments'
	{
		buf = tail[o2:]
		num, err := ssz.DivideInt2(len(buf), 48, 4096)
		if err != nil {
			return err
		}
		d.BlobKZGCommitments = make([]deneb.KZGCommitment, num)
		for ii := 0; ii < num; ii++ {
			copy(d.BlobKZGCommitments[ii][:], buf[ii*48:(ii+1)*48])
		}
	}
	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the DenebSubmitHeaderOptimistic object
func (d *DenebSubmitHeaderOptimistic) SizeSSZ() (size int) {
	size = 340

	// Field (1) 'ExecutionPayloadHeader'
	if d.ExecutionPayloadHeader == nil {
		d.ExecutionPayloadHeader = new(deneb.ExecutionPayloadHeader)
	}
	size += d.ExecutionPayloadHeader.SizeSSZ()

	// Field (2) 'BlobKZGCommitments'
	size += len(d.BlobKZGCommitments) * 48

	return
}
