package common

import (
	"testing"

	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/stretchr/testify/require"
)

func TestDataVersion(t *testing.T) {
	require.Equal(t, ForkVersionStringBellatrix, consensusspec.DataVersionBellatrix.String())
	require.Equal(t, ForkVersionStringCapella, consensusspec.DataVersionCapella.String())
	require.Equal(t, ForkVersionStringDeneb, consensusspec.DataVersionDeneb.String())
}
