package database

import (
	"database/sql"
	"errors"
	"math"
	"strconv"
	"time"

	builderApiV1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/flashbots/go-boost-utils/utils"
)

var errTimestampOverflow = errors.New("timestamp overflow")

func NewNullInt64(i int64) sql.NullInt64 {
	return sql.NullInt64{
		Int64: i,
		Valid: true,
	}
}

func NewNullString(s string) sql.NullString {
	return sql.NullString{
		String: s,
		Valid:  true,
	}
}

// NewNullTime returns a sql.NullTime with the given time.Time. If the time is
// the zero value, the NullTime is invalid.
func NewNullTime(t time.Time) sql.NullTime {
	return sql.NullTime{
		Time:  t,
		Valid: t != time.Time{},
	}
}

type GetPayloadsFilters struct {
	Slot           int64
	Cursor         int64
	Limit          uint64
	BlockHash      string
	BlockNumber    int64
	ProposerPubkey string
	BuilderPubkey  string
	OrderByValue   int8
}

type GetBuilderSubmissionsFilters struct {
	Slot          int64
	Limit         int64
	BlockHash     string
	BlockNumber   int64
	BuilderPubkey string
}

type ValidatorRegistrationEntry struct {
	ID         int64     `db:"id"`
	InsertedAt time.Time `db:"inserted_at"`
	Geo        Geo       `db:"geo"`

	Pubkey       string `db:"pubkey"`
	FeeRecipient string `db:"fee_recipient"`
	Timestamp    uint64 `db:"timestamp"`
	GasLimit     uint64 `db:"gas_limit"`
	Signature    string `db:"signature"`
}

func (reg ValidatorRegistrationEntry) ToSignedValidatorRegistration() (*builderApiV1.SignedValidatorRegistration, error) {
	pubkey, err := utils.HexToPubkey(reg.Pubkey)
	if err != nil {
		return nil, err
	}

	feeRec, err := utils.HexToAddress(reg.FeeRecipient)
	if err != nil {
		return nil, err
	}

	sig, err := utils.HexToSignature(reg.Signature)
	if err != nil {
		return nil, err
	}

	if reg.Timestamp > uint64(math.MaxInt64) {
		return nil, errTimestampOverflow
	}

	return &builderApiV1.SignedValidatorRegistration{
		Message: &builderApiV1.ValidatorRegistration{
			Pubkey:       pubkey,
			FeeRecipient: feeRec,
			Timestamp:    time.Unix(int64(reg.Timestamp), 0),
			GasLimit:     reg.GasLimit,
		},
		Signature: sig,
	}, nil
}

func SignedValidatorRegistrationToEntry(valReg builderApiV1.SignedValidatorRegistration) ValidatorRegistrationEntry {
	return ValidatorRegistrationEntry{
		Pubkey:       valReg.Message.Pubkey.String(),
		FeeRecipient: valReg.Message.FeeRecipient.String(),
		Timestamp:    uint64(valReg.Message.Timestamp.Unix()), //nolint:gosec
		GasLimit:     valReg.Message.GasLimit,
		Signature:    valReg.Signature.String(),
	}
}

type ExecutionPayloadEntry struct {
	ID         int64     `db:"id"`
	InsertedAt time.Time `db:"inserted_at"`

	Slot           uint64 `db:"slot"`
	ProposerPubkey string `db:"proposer_pubkey"`
	BlockHash      string `db:"block_hash"`

	Version string `db:"version"`
	Payload string `db:"payload"`
}

var ExecutionPayloadEntryCSVHeader = []string{"id", "inserted_at", "slot", "proposer_pubkey", "block_hash", "version", "payload"}

func (e *ExecutionPayloadEntry) ToCSVRecord() []string {
	return []string{
		strconv.FormatInt(e.ID, 10),
		e.InsertedAt.UTC().String(),
		strconv.FormatUint(e.Slot, 10),
		e.ProposerPubkey,
		e.BlockHash,
		e.Version,
		e.Payload,
	}
}

type BuilderBlockSubmissionEntry struct {
	ID         int64        `db:"id"`
	InsertedAt time.Time    `db:"inserted_at"`
	ReceivedAt sql.NullTime `db:"received_at"`
	EligibleAt sql.NullTime `db:"eligible_at"`

	// Delivered ExecutionPayload
	ExecutionPayloadID sql.NullInt64 `db:"execution_payload_id"`

	// Sim Result
	WasSimulated bool           `db:"was_simulated"`
	SimSuccess   bool           `db:"sim_success"`
	SimError     string         `db:"sim_error"`
	SimReqError  string         `db:"sim_req_error"`
	BlockValue   sql.NullString `db:"block_value"`

	// BidTrace data
	Signature string `db:"signature"`

	Slot       uint64 `db:"slot"`
	ParentHash string `db:"parent_hash"`
	BlockHash  string `db:"block_hash"`

	BuilderPubkey        string `db:"builder_pubkey"`
	ProposerPubkey       string `db:"proposer_pubkey"`
	ProposerFeeRecipient string `db:"proposer_fee_recipient"`

	GasUsed  uint64 `db:"gas_used"`
	GasLimit uint64 `db:"gas_limit"`

	NumTx uint64 `db:"num_tx"`
	Value string `db:"value"`

	// Helpers
	Epoch       uint64 `db:"epoch"`
	BlockNumber uint64 `db:"block_number"`

	// Profile data.
	DecodeDuration       uint64 `db:"decode_duration"`
	PrechecksDuration    uint64 `db:"prechecks_duration"`
	SimulationDuration   uint64 `db:"simulation_duration"`
	RedisUpdateDuration  uint64 `db:"redis_update_duration"`
	TotalDuration        uint64 `db:"total_duration"`
	OptimisticSubmission bool   `db:"optimistic_submission"`
}

type DeliveredPayloadEntry struct {
	ID         int64        `db:"id"`
	InsertedAt time.Time    `db:"inserted_at"`
	SignedAt   sql.NullTime `db:"signed_at"`
	Geo        Geo          `db:"geo"`

	SignedBlindedBeaconBlock sql.NullString `db:"signed_blinded_beacon_block"`

	Slot  uint64 `db:"slot"`
	Epoch uint64 `db:"epoch"`

	BuilderPubkey        string `db:"builder_pubkey"`
	ProposerPubkey       string `db:"proposer_pubkey"`
	ProposerFeeRecipient string `db:"proposer_fee_recipient"`

	ParentHash  string `db:"parent_hash"`
	BlockHash   string `db:"block_hash"`
	BlockNumber uint64 `db:"block_number"`

	GasUsed  uint64 `db:"gas_used"`
	GasLimit uint64 `db:"gas_limit"`

	NumTx uint64 `db:"num_tx"`
	Value string `db:"value"`

	NumBlobs      uint64 `db:"num_blobs"`
	BlobGasUsed   uint64 `db:"blob_gas_used"`
	ExcessBlobGas uint64 `db:"excess_blob_gas"`

	PublishMs uint64 `db:"publish_ms"`
}

type BlockBuilderEntry struct {
	ID         int64     `db:"id"          json:"id"`
	InsertedAt time.Time `db:"inserted_at" json:"inserted_at"`

	BuilderPubkey string `db:"builder_pubkey" json:"builder_pubkey"`
	Description   string `db:"description"    json:"description"`

	IsHighPrio    bool `db:"is_high_prio"   json:"is_high_prio"`
	IsBlacklisted bool `db:"is_blacklisted" json:"is_blacklisted"`
	IsOptimistic  bool `db:"is_optimistic"  json:"is_optimistic"`

	Collateral string `db:"collateral" json:"collateral"`
	BuilderID  string `db:"builder_id" json:"builder_id"`

	LastSubmissionID   sql.NullInt64 `db:"last_submission_id"   json:"last_submission_id"`
	LastSubmissionSlot uint64        `db:"last_submission_slot" json:"last_submission_slot"`

	NumSubmissionsTotal    uint64 `db:"num_submissions_total"    json:"num_submissions_total"`
	NumSubmissionsSimError uint64 `db:"num_submissions_simerror" json:"num_submissions_simerror"`

	NumSentGetPayload uint64 `db:"num_sent_getpayload" json:"num_sent_getpayload"`
}

type BuilderDemotionEntry struct {
	ID         int64     `db:"id"`
	InsertedAt time.Time `db:"inserted_at"`

	SubmitBlockRequest          sql.NullString `db:"submit_block_request"`
	SignedBeaconBlock           sql.NullString `db:"signed_beacon_block"`
	SignedValidatorRegistration sql.NullString `db:"signed_validator_registration"`

	Slot  uint64 `db:"slot"`
	Epoch uint64 `db:"epoch"`

	BuilderPubkey  string `db:"builder_pubkey"`
	ProposerPubkey string `db:"proposer_pubkey"`

	Value string `db:"value"`

	FeeRecipient string `db:"fee_recipient"`

	BlockHash string `db:"block_hash"`

	SimError string `db:"sim_error"`
}

type TooLateGetPayloadEntry struct {
	ID         int64     `db:"id"`
	InsertedAt time.Time `db:"inserted_at"`
	Geo        Geo       `db:"geo"`

	Slot uint64 `db:"slot"`

	SlotStartTimestamp uint64 `db:"slot_start_timestamp"`
	RequestTimestamp   uint64 `db:"request_timestamp"`
	DecodeTimestamp    uint64 `db:"decode_timestamp"`

	ProposerPubkey string `db:"proposer_pubkey"`
	BlockHash      string `db:"block_hash"`
	MsIntoSlot     uint64 `db:"ms_into_slot"`
}
