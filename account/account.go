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
	"fmt"

	"github.com/hyperledger/burrow/binary"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/permission"
	"github.com/tendermint/go-amino"
)

var GlobalAddress = crypto.Address(binary.Zero160)

// Account structure
type Account struct {
	data accountData
}

type accountData struct {
	Address     crypto.Address
	Sequence    uint64
	Balance     uint64
	Code        Bytecode
	StorageRoot []byte
	Permissions permission.Permissions
}

///---- Constructors
func NewAccount(address crypto.Address) *Account {
	return &Account{
		data: accountData{
			Address: address,
		},
	}
}

/// For tests
func NewAccountFromSecret(secret string) *Account {
	return NewAccount(crypto.PrivateKeyFromSecret(secret, crypto.CurveTypeEd25519).GetPublicKey().Address())
}

///---- Getter methods
func (acc Account) Address() crypto.Address             { return acc.data.Address }
func (acc Account) Balance() uint64                     { return acc.data.Balance }
func (acc Account) Code() Bytecode                      { return acc.data.Code }
func (acc Account) Sequence() uint64                    { return acc.data.Sequence }
func (acc Account) StorageRoot() []byte                 { return acc.data.StorageRoot }
func (acc Account) Permissions() permission.Permissions { return acc.data.Permissions }

func (acc Account) HasPermissions(permissions permission.Permissions) bool {
	return acc.data.Permissions.IsSet(permissions)
}

///---- Mutable methods
func (acc *Account) SubtractFromBalance(amount uint64) error {
	if amount > acc.Balance() {
		return fmt.Errorf("insufficient funds: attempt to subtract %v from the balance of %s",
			amount, acc.Address())
	}
	acc.data.Balance -= amount
	return nil
}

func (acc *Account) AddToBalance(amount uint64) error {
	if binary.IsUint64SumOverflow(acc.Balance(), amount) {
		return fmt.Errorf("uint64 overflow: attempt to add %v to the balance of %s",
			amount, acc.Address())
	}
	acc.data.Balance += amount
	return nil
}

func (acc *Account) SetCode(code []byte) error {
	acc.data.Code = code
	return nil
}

func (acc *Account) IncSequence() {
	acc.data.Sequence++
}

func (acc *Account) SetStorageRoot(storageRoot []byte) error {
	acc.data.StorageRoot = storageRoot
	return nil
}

func (acc *Account) SetPermissions(permissions permission.Permissions) (error, permission.Permissions) {
	if err := permissions.EnsureValid(); err != nil {
		return err, acc.Permissions()
	}

	acc.data.Permissions.Set(permissions)
	return nil, acc.Permissions()
}

func (acc *Account) UnsetPermissions(permissions permission.Permissions) (error, permission.Permissions) {
	if err := permissions.EnsureValid(); err != nil {
		return err, acc.Permissions()
	}

	acc.data.Permissions.Unset(permissions)
	return nil, acc.Permissions()
}

///---- Serialisation methods
var cdc = amino.NewCodec()

func (acc Account) Encode() ([]byte, error) {
	return cdc.MarshalBinary(acc.data)
}

func Decode(bytes []byte) (*Account, error) {
	var account Account

	err := cdc.UnmarshalBinary(bytes, &account.data)
	if err != nil {
		return nil, fmt.Errorf("could not convert decoded account to *ConcreteAccount: %v", err)
	}
	return &account, nil
}

func (acc Account) MarshalJSON() ([]byte, error) {
	return json.Marshal(acc.data)
}
func (acc *Account) UnmarshalJSON(bytes []byte) error {
	err := json.Unmarshal(bytes, &acc.data)
	if err != nil {
		// Don't swallow deserialisation errors
		return err
	}
	return nil
}

func (acc Account) String() string {
	return fmt.Sprintf("Account{Address: %s; Sequence: %v Balance: %v; CodeBytes: %v; StorageRoot: 0x%X; Permissions: %v}",
		acc.Address(), acc.Sequence(), acc.Balance(), len(acc.Code()), acc.StorageRoot(), acc.Permissions())
}
