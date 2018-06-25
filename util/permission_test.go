package util

import (
	"testing"

	acm "github.com/hyperledger/burrow/account"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/permission"
	"github.com/stretchr/testify/assert"
)

type fakeAccountGetter struct{}

func (fakeAccountGetter) GetAccount(address crypto.Address) (*acm.Account, error) {
	if address == acm.GlobalPermissionsAddress {
		globalAccount := acm.NewContractAccount(acm.GlobalPermissionsAddress, permission.Send|permission.Bond)
		return globalAccount, nil
	}

	return nil, nil
}

func TestHasPermission(t *testing.T) {
	var fakeGetter fakeAccountGetter

	acc := acm.NewAccountFromSecret("test", permission.Call)
	// Ensure we are falling through to global permissions on those bits not set
	assert.True(t, HasPermissions(fakeGetter, acc, permission.Call))
	assert.True(t, HasPermissions(fakeGetter, acc, permission.Send))
	assert.False(t, HasPermissions(fakeGetter, acc, permission.CreateAccount))

}
