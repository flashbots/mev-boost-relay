package api

import (
	"context"
)

type MockBlockSimulationRateLimiter struct {
	simulationError error
}

func (m *MockBlockSimulationRateLimiter) send(context context.Context, payload *BuilderBlockValidationRequest, isHighPrio bool) error {
	return m.simulationError
}

func (m *MockBlockSimulationRateLimiter) currentCounter() int64 {
	return 0
}
