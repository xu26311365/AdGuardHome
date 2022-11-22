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

func TestDefaultStorage_CRUD(t *testing.T) {
	var items []*Item

	s, err := NewDefaultStorage(-1, items)
	require.NoError(t, err)
	require.Equal(t, 0, len(s.List()))

	item := &Item{Domain: "example.com", Answer: "answer.com"}

	err = s.Add(item)
	require.NoError(t, err)

	list := s.List()
	require.Equal(t, 1, len(list))
	require.True(t, item.equal(list[0]))

	err = s.Remove(item)
	require.NoError(t, err)
	require.Equal(t, 0, len(s.List()))
}
