package container

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContainerLabel(t *testing.T) {
	cases := []struct {
		name string
		c    Container
		want string
	}{
		{"name and image", Container{Name: "web", Image: "node:22"}, "container web (node:22)"},
		{"no image", Container{Name: "web"}, "container web"},
		{"no name shows the short id", Container{ID: "0123456789abcdef0123", Image: "node:22"}, "container 0123456789ab (node:22)"},
		{"short id kept whole", Container{ID: "abc"}, "container abc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.c.Label())
		})
	}
}

func TestContainerIsZero(t *testing.T) {
	assert.True(t, Container{}.IsZero())
	assert.False(t, Container{ID: "abc"}.IsZero())
}
