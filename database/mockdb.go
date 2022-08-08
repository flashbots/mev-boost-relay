package database

import (
	"context"

	"github.com/flashbots/go-boost-utils/types"
)

type MockDB struct {
}

func (db MockDB) SaveValidatorRegistration(ctx context.Context, registration types.SignedValidatorRegistration) error {
	return nil
}

func (db MockDB) SaveDeliveredPayload(ctx context.Context, entry *DeliveredPayloadEntry) error {
	return nil
}

func (db MockDB) GetRecentDeliveredPayloads(ctx context.Context, filters GetPayloadsFilters) ([]*DeliveredPayloadEntry, error) {
	return nil, nil
}

func (db MockDB) SaveBuilderBlockSubmission(ctx context.Context, entry *BuilderBlockEntry) error {
	return nil
}
