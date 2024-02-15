package common

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	builderApiV1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"
	boostSsz "github.com/flashbots/go-boost-utils/ssz"
)

var (
	ErrUnknownNetwork = errors.New("unknown network")
	ErrEmptyPayload   = errors.New("empty payload")

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

/*
SubmitBlockRequestV2Optimistic is the v2 request from the builder to submit
a block. The message must be SSZ encoded. The first three fields are at most
944 bytes, which fit into a single 1500 MTU ethernet packet. The
`UnmarshalSSZHeaderOnly` function just parses the first three fields,
which is sufficient data to set the bid of the builder. The `Transactions`
and `Withdrawals` fields are required to construct the full SignedBeaconBlock
and are parsed asynchronously.

Header only layout:
[000-236) = Message   (236 bytes)
[236-240) = offset1   (  4 bytes)
[240-336) = Signature ( 96 bytes)
[336-340) = offset2   (  4 bytes)
[340-344) = offset3   (  4 bytes)
[344-944) = EPH       (600 bytes)
*/
type SubmitBlockRequestV2Optimistic struct {
	Message                *builderApiV1.BidTrace
	ExecutionPayloadHeader *capella.ExecutionPayloadHeader
	Signature              phase0.BLSSignature     `ssz-size:"96"`
	Transactions           []bellatrix.Transaction `ssz-max:"1048576,1073741824" ssz-size:"?,?"`
	Withdrawals            []*capella.Withdrawal   `ssz-max:"16"`
}

// MarshalSSZ ssz marshals the SubmitBlockRequestV2Optimistic object
func (s *SubmitBlockRequestV2Optimistic) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(s)
}

// UnmarshalSSZ ssz unmarshals the SubmitBlockRequestV2Optimistic object
func (s *SubmitBlockRequestV2Optimistic) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 344 {
		return ssz.ErrSize
	}

	tail := buf
	var o1, o3, o4 uint64

	// Field (0) 'Message'
	if s.Message == nil {
		s.Message = new(builderApiV1.BidTrace)
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
			s.ExecutionPayloadHeader = new(capella.ExecutionPayloadHeader)
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
		s.Transactions = make([]bellatrix.Transaction, num)
		err = ssz.UnmarshalDynamic(buf, num, func(indx int, buf []byte) (err error) {
			if len(buf) > 1073741824 {
				return ssz.ErrBytesLength
			}
			if cap(s.Transactions[indx]) == 0 {
				s.Transactions[indx] = bellatrix.Transaction(make([]byte, 0, len(buf)))
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
		s.Withdrawals = make([]*capella.Withdrawal, num)
		for ii := 0; ii < num; ii++ {
			if s.Withdrawals[ii] == nil {
				s.Withdrawals[ii] = new(capella.Withdrawal)
			}
			if err = s.Withdrawals[ii].UnmarshalSSZ(buf[ii*44 : (ii+1)*44]); err != nil {
				return err
			}
		}
	}
	return err
}

// UnmarshalSSZHeaderOnly ssz unmarshals the first 3 fields of the SubmitBlockRequestV2Optimistic object
func (s *SubmitBlockRequestV2Optimistic) UnmarshalSSZHeaderOnly(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 344 {
		return ssz.ErrSize
	}

	tail := buf
	var o1, o3 uint64

	// Field (0) 'Message'
	if s.Message == nil {
		s.Message = new(builderApiV1.BidTrace)
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
			s.ExecutionPayloadHeader = new(capella.ExecutionPayloadHeader)
		}
		if err = s.ExecutionPayloadHeader.UnmarshalSSZ(buf); err != nil {
			return err
		}
	}
	return err
}

// MarshalSSZTo ssz marshals the SubmitBlockRequestV2Optimistic object to a target array
func (s *SubmitBlockRequestV2Optimistic) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := int(344)

	// Field (0) 'Message'
	if s.Message == nil {
		s.Message = new(builderApiV1.BidTrace)
	}
	if dst, err = s.Message.MarshalSSZTo(dst); err != nil {
		return nil, err
	}

	// Offset (1) 'ExecutionPayloadHeader'
	dst = ssz.WriteOffset(dst, offset)
	if s.ExecutionPayloadHeader == nil {
		s.ExecutionPayloadHeader = new(capella.ExecutionPayloadHeader)
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
		return nil, err
	}

	// Field (3) 'Transactions'
	if size := len(s.Transactions); size > 1073741824 {
		err = ssz.ErrListTooBigFn("SubmitBlockRequestV2Optimistic.Transactions", size, 1073741824)
		return nil, err
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
			err = ssz.ErrBytesLengthFn("SubmitBlockRequestV2Optimistic.Transactions[ii]", size, 1073741824)
			return nil, err
		}
		dst = append(dst, s.Transactions[ii]...)
	}

	// Field (4) 'Withdrawals'
	if size := len(s.Withdrawals); size > 16 {
		err = ssz.ErrListTooBigFn("SubmitBlockRequestV2Optimistic.Withdrawals", size, 16)
		return nil, err
	}
	for ii := 0; ii < len(s.Withdrawals); ii++ {
		if dst, err = s.Withdrawals[ii].MarshalSSZTo(dst); err != nil {
			return nil, err
		}
	}
	return dst, nil
}

// SizeSSZ returns the ssz encoded size in bytes for the SubmitBlockRequestV2Optimistic object
func (s *SubmitBlockRequestV2Optimistic) SizeSSZ() (size int) {
	size = 344

	// Field (1) 'ExecutionPayloadHeader'
	if s.ExecutionPayloadHeader == nil {
		s.ExecutionPayloadHeader = new(capella.ExecutionPayloadHeader)
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
