package rewrite

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewDefaultStorage(t *testing.T) {
	items := []*Item{{
		Domain: "example.com",
		Answer: "answer.com",
	}}

	s, err := NewDefaultStorage(-1, items)
	require.NoError(t, err)

	require.Equal(t, 1, len(s.List()))
}
