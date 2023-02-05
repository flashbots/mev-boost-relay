package database

import (
	"fmt"
	"time"

	"github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost-relay/common"
)

type MockDB struct {
	Builders  map[string]*BlockBuilderEntry
	Demotions map[string]bool
	Refunds   map[string]bool
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

func (db MockDB) SaveBuilderBlockSubmission(payload *types.BuilderSubmitBlockRequest, simError error, receivedAt time.Time) (entry *BuilderBlockSubmissionEntry, err error) {
	return nil, nil
}

func (db MockDB) GetExecutionPayloadEntryByID(executionPayloadID int64) (entry *ExecutionPayloadEntry, err error) {
	return nil, nil
}

func (db MockDB) GetExecutionPayloadEntryBySlotPkHash(slot uint64, proposerPubkey, blockHash string) (entry *ExecutionPayloadEntry, err error) {
	return nil, nil
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

func (db MockDB) SaveDeliveredPayload(bidTrace *common.BidTraceV2, signedBlindedBeaconBlock *types.SignedBlindedBeaconBlock) error {
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
		return nil, fmt.Errorf("builder with pubkey %v not in Builders map", pubkey)
	}
	return builder, nil
}

func (db MockDB) SetBlockBuilderStatus(pubkey string, status common.BuilderStatus) error {
	builder, ok := db.Builders[pubkey]
	if !ok {
		return fmt.Errorf("builder with pubkey %v not in Builders map", pubkey)
	}
	// Single builder update.
	if builder.CollateralID == "" {
		builder.IsHighPrio = status.IsHighPrio
		builder.IsBlacklisted = status.IsBlacklisted
		builder.IsDemoted = status.IsDemoted
		return nil
	}
	// All matching collateral IDs updated.
	for _, v := range db.Builders {
		if v.CollateralID == builder.CollateralID {
			v.IsHighPrio = status.IsHighPrio
			v.IsBlacklisted = status.IsBlacklisted
			v.IsDemoted = status.IsDemoted
		}
	}
	return nil
}

func (db MockDB) SetBlockBuilderCollateral(pubkey, collateralID, collateralValue string) error {
	builder, ok := db.Builders[pubkey]
	if !ok {
		return fmt.Errorf("builder with pubkey %v not in Builders map", pubkey)
	}
	builder.CollateralID = collateralID
	builder.CollateralValue = collateralValue
	return nil
}

func (db MockDB) IncBlockBuilderStatsAfterGetHeader(slot uint64, blockhash string) error {
	return nil
}

func (db MockDB) IncBlockBuilderStatsAfterGetPayload(builderPubkey string) error {
	return nil
}

func (db MockDB) UpsertBuilderDemotion(submitBlockRequest *types.BuilderSubmitBlockRequest, signedBeaconBlock *types.SignedBeaconBlock, signedValidatorRegistration *types.SignedValidatorRegistration) error {
	pubkey := submitBlockRequest.Message.BuilderPubkey.String()
	db.Demotions[pubkey] = true

	// Refundable case.
	if signedBeaconBlock != nil {
		db.Refunds[pubkey] = true
	}
	return nil
}
