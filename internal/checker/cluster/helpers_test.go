package cluster

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsSystemNamespace(t *testing.T) {
	assert.True(t, isSystemNamespace("kube-system"))
	assert.True(t, isSystemNamespace("kube-public"))
	assert.True(t, isSystemNamespace("kube-node-lease"))
	assert.False(t, isSystemNamespace("default"))
	assert.False(t, isSystemNamespace("production"))
}
