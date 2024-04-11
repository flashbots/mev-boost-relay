package database

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewNullTime(t *testing.T) {
	var t1 time.Time
	nt1 := NewNullTime(t1)
	require.False(t, nt1.Valid)

	t1 = time.Now()
	nt1 = NewNullTime(t1)
	require.True(t, nt1.Valid)
	require.Equal(t, t1, nt1.Time)
}
