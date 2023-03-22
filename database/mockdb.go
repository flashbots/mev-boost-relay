package database

import (
	"errors"
	"sync"
	"time"

	"github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost-relay/common"
)

var (
	errNoBuilder  = errors.New("builder entry not present in builder map")
	errNotDemoted = errors.New("builder is not demoted")
)

type MockDB struct {
	Builders  map[string]*BlockBuilderEntry
	Demotions map[string]bool
	Refunds   map[string]bool
	mu        sync.Mutex
}

func (db *MockDB) NumRegisteredValidators() (count uint64, err error) {
	return 0, nil
}

func (db *MockDB) SaveValidatorRegistration(entry ValidatorRegistrationEntry) error {
	return nil
}

func (db *MockDB) GetValidatorRegistration(pubkey string) (*ValidatorRegistrationEntry, error) {
	return nil, nil
}

func (db *MockDB) GetValidatorRegistrationsForPubkeys(pubkeys []string) (entries []*ValidatorRegistrationEntry, err error) {
	return nil, nil
}

func (db *MockDB) GetLatestValidatorRegistrations(timestampOnly bool) ([]*ValidatorRegistrationEntry, error) {
	return nil, nil
}

func (db *MockDB) SaveBuilderBlockSubmission(payload *common.BuilderSubmitBlockRequest, simError error, receivedAt, eligibleAt time.Time, saveExecPayload bool, profile common.Profile, optimisticSubmission bool) (entry *BuilderBlockSubmissionEntry, err error) {
	return nil, nil
}

func (db *MockDB) GetExecutionPayloadEntryByID(executionPayloadID int64) (entry *ExecutionPayloadEntry, err error) {
	return nil, nil
}

func (db *MockDB) GetExecutionPayloadEntryBySlotPkHash(slot uint64, proposerPubkey, blockHash string) (entry *ExecutionPayloadEntry, err error) {
	return nil, nil
}

func (db *MockDB) GetExecutionPayloads(idFirst, idLast uint64) (entries []*ExecutionPayloadEntry, err error) {
	return nil, nil
}

func (db *MockDB) DeleteExecutionPayloads(idFirst, idLast uint64) error {
	return nil
}

func (db *MockDB) GetBlockSubmissionEntry(slot uint64, proposerPubkey, blockHash string) (entry *BuilderBlockSubmissionEntry, err error) {
	return nil, nil
}

func (db *MockDB) GetRecentDeliveredPayloads(filters GetPayloadsFilters) ([]*DeliveredPayloadEntry, error) {
	return nil, nil
}

func (db *MockDB) GetDeliveredPayloads(idFirst, idLast uint64) (entries []*DeliveredPayloadEntry, err error) {
	return nil, nil
}

func (db *MockDB) GetNumDeliveredPayloads() (uint64, error) {
	return 0, nil
}

func (db *MockDB) GetBuilderSubmissions(filters GetBuilderSubmissionsFilters) ([]*BuilderBlockSubmissionEntry, error) {
	return nil, nil
}

func (db *MockDB) GetBuilderSubmissionsBySlots(slotFrom, slotTo uint64) (entries []*BuilderBlockSubmissionEntry, err error) {
	return nil, nil
}

func (db *MockDB) SaveDeliveredPayload(bidTrace *common.BidTraceV2, signedBlindedBeaconBlock *common.SignedBlindedBeaconBlock, signedAt time.Time) error {
	return nil
}

func (db *MockDB) UpsertBlockBuilderEntryAfterSubmission(lastSubmission *BuilderBlockSubmissionEntry, isError bool) error {
	return nil
}

func (db *MockDB) GetBlockBuilders() ([]*BlockBuilderEntry, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	res := []*BlockBuilderEntry{}
	for _, v := range db.Builders {
		res = append(res, v)
	}
	return res, nil
}

func (db *MockDB) GetBlockBuilderByPubkey(pubkey string) (*BlockBuilderEntry, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	builder, ok := db.Builders[pubkey]
	if !ok {
		return nil, errNoBuilder
	}
	return builder, nil
}

func (db *MockDB) SetBlockBuilderStatus(pubkey string, status common.BuilderStatus) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	builder, ok := db.Builders[pubkey]
	if !ok {
		return errNoBuilder
	}
	// Single builder update.
	if builder.BuilderID == "" {
		builder.IsHighPrio = status.IsHighPrio
		builder.IsBlacklisted = status.IsBlacklisted
		builder.IsOptimistic = status.IsOptimistic
		return nil
	}
	// All matching collateral IDs updated.
	for _, v := range db.Builders {
		if v.BuilderID == builder.BuilderID {
			v.IsHighPrio = status.IsHighPrio
			v.IsBlacklisted = status.IsBlacklisted
			v.IsOptimistic = status.IsOptimistic
		}
	}
	return nil
}

func (db *MockDB) SetBlockBuilderCollateral(pubkey, builderID, collateral string) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	builder, ok := db.Builders[pubkey]
	if !ok {
		return errNoBuilder
	}
	builder.BuilderID = builderID
	builder.Collateral = collateral
	return nil
}

func (db *MockDB) IncBlockBuilderStatsAfterGetHeader(slot uint64, blockhash string) error {
	return nil
}

func (db *MockDB) IncBlockBuilderStatsAfterGetPayload(builderPubkey string) error {
	return nil
}

func (db *MockDB) InsertBuilderDemotion(submitBlockRequest *common.BuilderSubmitBlockRequest, simError error) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	pubkey := submitBlockRequest.BuilderPubkey().String()
	db.Demotions[pubkey] = true
	return nil
}

func (db *MockDB) UpdateBuilderDemotion(trace *common.BidTraceV2, signedBlock *common.SignedBeaconBlock, signedRegistration *types.SignedValidatorRegistration) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	pubkey := trace.BuilderPubkey.String()
	_, ok := db.Builders[pubkey]
	if !ok {
		return errNoBuilder
	}
	if !db.Demotions[pubkey] {
		return errNotDemoted
	}
	db.Refunds[pubkey] = true
	return nil
}

func (db *MockDB) GetBuilderDemotion(trace *common.BidTraceV2) (*BuilderDemotionEntry, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	pubkey := trace.BuilderPubkey.String()
	_, ok := db.Builders[pubkey]
	if !ok {
		return nil, errNoBuilder
	}
	if db.Demotions[pubkey] {
		return &BuilderDemotionEntry{}, nil
	}
	return nil, nil
}
