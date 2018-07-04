// Copyright 2017 Monax Industries Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package account

import (
	"encoding/json"
	"testing"

	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/permission"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddress(t *testing.T) {
	bs := []byte{
		1, 2, 3, 4, 5,
		1, 2, 3, 4, 5,
		1, 2, 3, 4, 5,
		1, 2, 3, 4, 5,
	}
	addr, err := crypto.AddressFromBytes(bs)
	assert.NoError(t, err)
	word256 := addr.Word256()
	leadingZeroes := []byte{
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
	}
	assert.Equal(t, leadingZeroes, word256[:12])
	addrFromWord256 := crypto.AddressFromWord256(word256)
	assert.Equal(t, bs, addrFromWord256[:])
	assert.Equal(t, addr, addrFromWord256)
}

func TestDecode(t *testing.T) {
	acc := NewAccountFromSecret("Super Semi Secret")
	acc.AddToBalance(100)

	encodedAcc, err := acc.Encode()
	require.NoError(t, err)
	accOut, err := Decode(encodedAcc)
	require.NoError(t, err)
	assert.Equal(t, acc, accOut)

	accOut, err = Decode([]byte("flungepliffery munknut tolopops"))
	require.Error(t, err)
	assert.Nil(t, accOut)
}

func TestMarshalJSON(t *testing.T) {
	acc1 := NewAccountFromSecret("Secret")
	acc1.SetPermissions(permission.Send | permission.CreateContract)
	acc1.AddToBalance(100)
	acc1.IncSequence()
	acc1.SetStorageRoot([]byte{1, 2, 3, 4, 5})
	acc1.SetCode([]byte{60, 23, 45})

	bs, err1 := json.Marshal(acc1)
	require.NoError(t, err1)

	var acc2 Account
	err2 := json.Unmarshal(bs, &acc2)
	require.NoError(t, err2)

	assert.Equal(t, *acc1, acc2)
}

func TestPermissions(t *testing.T) {
	account := NewAccountFromSecret("Super Semi Secret")
	account.SetPermissions(permission.Call)
	assert.Equal(t, account.Permissions(), permission.Call)
	account.SetPermissions(permission.CreateChain)
	assert.Equal(t, account.Permissions(), permission.Call|permission.CreateChain)
	assert.Equal(t, account.HasPermissions(permission.InterChainTx), false)
	account.UnsetPermissions(permission.CreateChain)
	assert.Equal(t, account.Permissions(), permission.Call)
}
