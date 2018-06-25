package permission

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAllPermissions(t *testing.T) {
	assert.Equal(t, AllAccountPermissions, DefaultAccountPermissions|ModifyPermission|CreateChain|InterChainTx)
}

func TestValidity(t *testing.T) {
	p1 := Reserved
	p2 := Permissions(0xFFFFFFFFFFFFFFFF)
	p3 := Call

	assert.Error(t, p1.EnsureValid())
	assert.Error(t, p2.EnsureValid())
	assert.NoError(t, p3.EnsureValid())
}

func TestModifying(t *testing.T) {
	p1 := Send
	p2 := Send
	p3 := Send | Call
	p2.Set(Call)
	p3.Unset(Call)

	assert.NotEqual(t, p1, p2)
	assert.Equal(t, p1, p3)
	assert.Equal(t, p1.IsSet(Call), false)
	assert.Equal(t, p2.IsSet(Call), true)
}
