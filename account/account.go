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
	ptypes "github.com/hyperledger/burrow/permission/types"
	"github.com/tendermint/go-amino"
)

var GlobalPermissionsAddress = crypto.Address(binary.Zero160)

type Addressable interface {
	// Get the 20 byte EVM address of this account
	Address() crypto.Address
	// Public key from which the Address is derived
	PublicKey() crypto.PublicKey
}

// Account structure
type Account struct {
	data accountData
}

type accountData struct {
	Address     crypto.Address
	PublicKey   crypto.PublicKey
	Sequence    uint64
	Balance     uint64
	Code        Bytecode
	StorageRoot []byte
	Permissions ptypes.AccountPermissions
}

///---- Constructors
func NewAccount(pubKey crypto.PublicKey, permissions ptypes.AccountPermissions) *Account {
	return &Account{
		data: accountData{
			Address:     pubKey.Address(),
			PublicKey:   pubKey,
			Permissions: permissions,
		},
	}
}

func NewContractAccount(address crypto.Address, permissions ptypes.AccountPermissions) *Account {
	return &Account{
		data: accountData{
			Address:     address,
			PublicKey:   crypto.PublicKey{},
			Permissions: permissions,
		},
	}
}

/// For tests
func NewAccountFromSecret(secret string, permissions ptypes.AccountPermissions) *Account {
	return NewAccount(crypto.PrivateKeyFromSecret(secret, crypto.CurveTypeEd25519).GetPublicKey(),
		permissions)
}

func NewContractAccountFromSecret(secret string, permissions ptypes.AccountPermissions) *Account {
	addr := crypto.NewContractAddress(crypto.PrivateKeyFromSecret(secret, crypto.CurveTypeEd25519).GetPublicKey().Address(), 1)
	return NewContractAccount(addr, permissions)
}

///---- Getter methods
func (acc Account) Address() crypto.Address                { return acc.data.Address }
func (acc Account) PublicKey() crypto.PublicKey            { return acc.data.PublicKey }
func (acc Account) Balance() uint64                        { return acc.data.Balance }
func (acc Account) Code() Bytecode                         { return acc.data.Code }
func (acc Account) Sequence() uint64                       { return acc.data.Sequence }
func (acc Account) StorageRoot() []byte                    { return acc.data.StorageRoot }
func (acc Account) Permissions() ptypes.AccountPermissions { return acc.data.Permissions }

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

func (acc *Account) SetPermissions(permissions ptypes.AccountPermissions) error {
	acc.data.Permissions = permissions
	return nil
}

func (acc *Account) MutablePermissions() *ptypes.AccountPermissions {
	return &acc.data.Permissions
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
	return fmt.Sprintf("Account{Address: %s; Sequence: %v; PublicKey: %v Balance: %v; CodeBytes: %v; StorageRoot: 0x%X; Permissions: %s}",
		acc.Address(), acc.Sequence(), acc.PublicKey(), acc.Balance(), len(acc.Code()), acc.StorageRoot(), acc.Permissions())
}
