package rewrite

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewDefaultStorage(t *testing.T) {
	c := &DefaultStorageConfig{
		rulesText: []string{
			"|a-record^$dnsrewrite=127.0.0.1",
		},
	}

	s, err := NewDefaultStorage(-1, c)
	require.NoError(t, err)

	require.Equal(t, 1, len(s.ReadRules()))
}
