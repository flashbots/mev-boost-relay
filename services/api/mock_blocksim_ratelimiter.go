package api

import (
	"context"

	"github.com/flashbots/mev-boost-relay/common"
)

type MockBlockSimulationRateLimiter struct {
	simulationError error
}

func (m *MockBlockSimulationRateLimiter) Send(context context.Context, payload *common.BuilderBlockValidationRequest, isHighPrio, fastTrack bool) (*common.BuilderBlockValidationResponse, error, error) {
	return nil, nil, m.simulationError
}

func (m *MockBlockSimulationRateLimiter) CurrentCounter() int64 {
	return 0
}
