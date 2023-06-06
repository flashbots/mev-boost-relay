package database

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost-relay/common"
)

type MockDB struct {
	ExecPayloads map[string]*ExecutionPayloadEntry
	Builders     map[string]*BlockBuilderEntry
	Demotions    map[string]bool
	Refunds      map[string]bool
}

func (db MockDB) NumRegisteredValidators() (count uint64, err error) {
	return 0, nil
}

func (db MockDB) SaveValidatorRegistration(entry ValidatorRegistrationEntry) error {
	return nil
}

func (db MockDB) GetValidatorRegistration(pubkey string) (*ValidatorRegistrationEntry, error) {
	return nil, nil
}

func (db MockDB) GetValidatorRegistrationsForPubkeys(pubkeys []string) (entries []*ValidatorRegistrationEntry, err error) {
	return nil, nil
}

func (db MockDB) GetLatestValidatorRegistrations(timestampOnly bool) ([]*ValidatorRegistrationEntry, error) {
	return nil, nil
}

func (db MockDB) SaveBuilderBlockSubmission(payload *common.BuilderSubmitBlockRequest, requestError, validationError error, receivedAt, eligibleAt time.Time, wasSimulated, saveExecPayload bool, profile common.Profile, optimisticSubmission bool) (entry *BuilderBlockSubmissionEntry, err error) {
	return nil, nil
}

func (db MockDB) GetExecutionPayloadEntryByID(executionPayloadID int64) (entry *ExecutionPayloadEntry, err error) {
	return nil, nil
}

func (db MockDB) GetExecutionPayloadEntryBySlotPkHash(slot uint64, proposerPubkey, blockHash string) (entry *ExecutionPayloadEntry, err error) {
	key := fmt.Sprintf("%d-%s-%s", slot, proposerPubkey, blockHash)
	entry, ok := db.ExecPayloads[key]
	if !ok {
		return nil, sql.ErrNoRows
	}
	return entry, nil
}

func (db MockDB) GetExecutionPayloads(idFirst, idLast uint64) (entries []*ExecutionPayloadEntry, err error) {
	return nil, nil
}

func (db MockDB) DeleteExecutionPayloads(idFirst, idLast uint64) error {
	return nil
}

func (db MockDB) GetBlockSubmissionEntry(slot uint64, proposerPubkey, blockHash string) (entry *BuilderBlockSubmissionEntry, err error) {
	return nil, nil
}

func (db MockDB) GetRecentDeliveredPayloads(filters GetPayloadsFilters) ([]*DeliveredPayloadEntry, error) {
	return nil, nil
}

func (db MockDB) GetDeliveredPayloads(idFirst, idLast uint64) (entries []*DeliveredPayloadEntry, err error) {
	return nil, nil
}

func (db MockDB) GetNumDeliveredPayloads() (uint64, error) {
	return 0, nil
}

func (db MockDB) GetBuilderSubmissions(filters GetBuilderSubmissionsFilters) ([]*BuilderBlockSubmissionEntry, error) {
	return nil, nil
}

func (db MockDB) GetBuilderSubmissionsBySlots(slotFrom, slotTo uint64) (entries []*BuilderBlockSubmissionEntry, err error) {
	return nil, nil
}

func (db MockDB) SaveDeliveredPayload(bidTrace *common.BidTraceV2, signedBlindedBeaconBlock *common.SignedBlindedBeaconBlock, signedAt time.Time, publishMs uint64) error {
	return nil
}

func (db MockDB) UpsertBlockBuilderEntryAfterSubmission(lastSubmission *BuilderBlockSubmissionEntry, isError bool) error {
	return nil
}

func (db MockDB) GetBlockBuilders() ([]*BlockBuilderEntry, error) {
	res := []*BlockBuilderEntry{}
	for _, v := range db.Builders {
		res = append(res, v)
	}
	return res, nil
}

func (db MockDB) GetBlockBuilderByPubkey(pubkey string) (*BlockBuilderEntry, error) {
	builder, ok := db.Builders[pubkey]
	if !ok {
		return nil, fmt.Errorf("builder with pubkey %v not in Builders map", pubkey) //nolint:goerr113
	}
	return builder, nil
}

func (db MockDB) SetBlockBuilderStatus(pubkey string, status common.BuilderStatus) error {
	builder, ok := db.Builders[pubkey]
	if !ok {
		return fmt.Errorf("builder with pubkey %v not in Builders map", pubkey) //nolint:goerr113
	}

	// Single key.
	builder.IsHighPrio = status.IsHighPrio
	builder.IsBlacklisted = status.IsBlacklisted
	builder.IsOptimistic = status.IsOptimistic
	return nil
}

func (db MockDB) SetBlockBuilderIDStatusIsOptimistic(pubkey string, isOptimistic bool) error {
	builder, ok := db.Builders[pubkey]
	if !ok {
		return fmt.Errorf("builder with pubkey %v not in Builders map", pubkey) //nolint:goerr113
	}
	for _, v := range db.Builders {
		if v.BuilderID == builder.BuilderID {
			v.IsOptimistic = isOptimistic
		}
	}
	return nil
}

func (db MockDB) SetBlockBuilderCollateral(pubkey, builderID, collateral string) error {
	builder, ok := db.Builders[pubkey]
	if !ok {
		return fmt.Errorf("builder with pubkey %v not in Builders map", pubkey) //nolint:goerr113
	}
	builder.BuilderID = builderID
	builder.Collateral = collateral
	return nil
}

func (db MockDB) IncBlockBuilderStatsAfterGetHeader(slot uint64, blockhash string) error {
	return nil
}

func (db MockDB) IncBlockBuilderStatsAfterGetPayload(builderPubkey string) error {
	return nil
}

func (db MockDB) InsertBuilderDemotion(submitBlockRequest *common.BuilderSubmitBlockRequest, simError error) error {
	pubkey := submitBlockRequest.BuilderPubkey().String()
	db.Demotions[pubkey] = true
	return nil
}

func (db MockDB) UpdateBuilderDemotion(trace *common.BidTraceV2, signedBlock *common.SignedBeaconBlock, signedRegistration *types.SignedValidatorRegistration) error {
	pubkey := trace.BuilderPubkey.String()
	_, ok := db.Builders[pubkey]
	if !ok {
		return fmt.Errorf("builder with pubkey %v not in Builders map", pubkey) //nolint:goerr113
	}
	if !db.Demotions[pubkey] {
		return fmt.Errorf("builder with pubkey %v is not demoted", pubkey) //nolint:goerr113
	}
	db.Refunds[pubkey] = true
	return nil
}

func (db MockDB) GetBuilderDemotion(trace *common.BidTraceV2) (*BuilderDemotionEntry, error) {
	pubkey := trace.BuilderPubkey.String()
	_, ok := db.Builders[pubkey]
	if !ok {
		return nil, fmt.Errorf("builder with pubkey %v not in Builders map", pubkey) //nolint:goerr113
	}
	if db.Demotions[pubkey] {
		return &BuilderDemotionEntry{}, nil
	}
	return nil, nil
}

func (db MockDB) GetTooLateGetPayload(slot uint64) (entries []*TooLateGetPayloadEntry, err error) {
	return nil, nil
}

func (db MockDB) InsertTooLateGetPayload(slot uint64, proposerPubkey, blockHash string, slotStart, requestTime, decodeTime, msIntoSlot uint64) error {
	return nil
}
