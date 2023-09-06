package api

import (
	"context"

	"github.com/flashbots/mev-boost-relay/common"
)

type MockBlockSimulationRateLimiter struct {
	overrides       common.BuilderBlockValidationResponseV2
	simulationError error
}

func (m *MockBlockSimulationRateLimiter) Send(context context.Context, payload *common.BuilderBlockValidationRequest, isHighPrio, fastTrack bool) (
	*common.BuilderBlockValidationResponseV2, error, error,
) {
	return &m.overrides, nil, m.simulationError
}

func (m *MockBlockSimulationRateLimiter) CurrentCounter() int64 {
	return 0
}
