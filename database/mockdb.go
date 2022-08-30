package database

import "github.com/flashbots/go-boost-utils/types"

type MockDB struct{}

func (db MockDB) SaveValidatorRegistration(registration types.SignedValidatorRegistration) error {
	return nil
}

func (db MockDB) SaveBuilderBlockSubmission(payload *types.BuilderSubmitBlockRequest, simError error) (id int64, err error) {
	return 0, nil
}

func (db MockDB) GetExecutionPayloadEntryByID(executionPayloadID int64) (entry *ExecutionPayloadEntry, err error) {
	return nil, nil
}

func (db MockDB) GetExecutionPayloadEntryBySlotPkHash(slot uint64, proposerPubkey, blockHash string) (entry *ExecutionPayloadEntry, err error) {
	return nil, nil
}

func (db MockDB) GetBlockSubmissionEntry(slot uint64, proposerPubkey, blockHash string) (entry *BuilderBlockSubmissionEntry, err error) {
	return nil, nil
}

func (db MockDB) GetRecentDeliveredPayloads(filters GetPayloadsFilters) ([]*DeliveredPayloadEntry, error) {
	return nil, nil
}

func (db MockDB) GetNumDeliveredPayloads() (uint64, error) {
	return 0, nil
}

func (db MockDB) GetBuilderSubmissions(filters GetBuilderSubmissionsFilters) ([]*BuilderBlockSubmissionEntry, error) {
	return nil, nil
}

func (db MockDB) SaveDeliveredPayload(slot uint64, proposerPubkey types.PubkeyHex, blockHash types.Hash, signedBlindedBeaconBlock *types.SignedBlindedBeaconBlock) error {
	return nil
}
