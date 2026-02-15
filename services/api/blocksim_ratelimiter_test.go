package api

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNoopBlockSim(t *testing.T) {
	n := newNoopBlockSim()
	resp, err1, err2 := n.Send(context.Background(), nil, false, false)
	require.NoError(t, err1)
	require.NoError(t, err2)
	require.Nil(t, resp)
}
