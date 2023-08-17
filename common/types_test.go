package common

import (
	"testing"

	"github.com/attestantio/go-eth2-client/spec"
	"github.com/stretchr/testify/require"
)

func TestDataVersion(t *testing.T) {
	require.Equal(t, ForkVersionStringBellatrix, spec.DataVersionBellatrix.String())
	require.Equal(t, ForkVersionStringCapella, spec.DataVersionCapella.String())
	require.Equal(t, ForkVersionStringDeneb, spec.DataVersionDeneb.String())
}
