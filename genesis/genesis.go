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

package genesis

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	acm "github.com/hyperledger/burrow/account"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/permission"
)

// How many bytes to take from the front of the GenesisDoc hash to append
// to the ChainName to form the ChainID. The idea is to avoid some classes
// of replay attack between chains with the same name.
const ShortHashSuffixBytes = 3

//------------------------------------------------------------
// core types for a genesis definition

type genAccount struct {
	Address     crypto.Address
	PublicKey   crypto.PublicKey
	Amount      uint64
	Name        string
	Permissions permission.Permissions
}

type genValidator struct {
	Address   crypto.Address
	PublicKey crypto.PublicKey
	Stake     uint64
}

//------------------------------------------------------------
// GenesisDoc is stored in the state database
type GenesisDoc struct {
	GenesisTime       time.Time
	ChainName         string
	Salt              []byte `json:",omitempty" toml:",omitempty"`
	GlobalPermissions permission.Permissions
	MaximumPower      int
	GenAccounts       []genAccount   `json:"Accounts" toml:"Accounts"`
	GenValidators     []genValidator `json:"Validators" toml:"Validators"`
}

// JSONBytes returns the JSON (not-yet) canonical bytes for a given
// GenesisDoc or an error.
func (genesisDoc *GenesisDoc) JSONBytes() ([]byte, error) {
	// TODO: write JSON in canonical order
	return json.MarshalIndent(genesisDoc, "", "\t")
}

func (genesisDoc *GenesisDoc) Hash() []byte {
	genesisDocBytes, err := genesisDoc.JSONBytes()
	if err != nil {
		panic(fmt.Errorf("could not create hash of GenesisDoc: %v", err))
	}
	hasher := sha256.New()
	hasher.Write(genesisDocBytes)
	return hasher.Sum(nil)
}

func (genesisDoc *GenesisDoc) ShortHash() []byte {
	return genesisDoc.Hash()[:ShortHashSuffixBytes]
}

func (genesisDoc *GenesisDoc) ChainID() string {
	return fmt.Sprintf("%s-%X", genesisDoc.ChainName, genesisDoc.ShortHash())
}

func (genesisDoc *GenesisDoc) Accounts() []*acm.Account {
	accounts := make([]*acm.Account, 0, len(genesisDoc.GenAccounts))
	for _, genAccount := range genesisDoc.GenAccounts {
		account := acm.NewAccount(genAccount.Address)
		account.SetPermissions(genAccount.Permissions)
		account.AddToBalance(genAccount.Amount)

		accounts = append(accounts, account)
	}

	return accounts
}

func (genesisDoc *GenesisDoc) names() map[crypto.Address]string {
	names := make(map[crypto.Address]string)
	for _, genAccount := range genesisDoc.GenAccounts {
		if genAccount.Name != "" {
			names[genAccount.Address] = genAccount.Name
		}
	}

	return names
}

func (genesisDoc *GenesisDoc) Validators() []acm.Validator {
	validators := make([]acm.Validator, 0, len(genesisDoc.GenValidators))
	for _, genValidator := range genesisDoc.GenValidators {
		account := acm.NewAccount(genValidator.Address)
		account.AddToBalance(genValidator.Stake)

		validator := acm.AsValidator(account, genValidator.PublicKey)

		validators = append(validators, validator)
	}

	return validators
}

func (genesisDoc *GenesisDoc) GetMaximumPower() int {
	if genesisDoc.MaximumPower < len(genesisDoc.GenValidators) {
		return len(genesisDoc.GenValidators)
	}

	return genesisDoc.MaximumPower
}

//------------------------------------------------------------
// Make genesis state from file

func GenesisDocFromJSON(jsonBlob []byte) (*GenesisDoc, error) {
	genDoc := new(GenesisDoc)
	err := json.Unmarshal(jsonBlob, genDoc)
	if err != nil {
		return nil, fmt.Errorf("couldn't read GenesisDoc: %v", err)
	}
	return genDoc, nil
}

//------------------------------------------------------------
// Account methods

func makeGenesisAccount(account *acm.Account) genAccount {
	return genAccount{
		Address:     account.Address(),
		Amount:      account.Balance(),
		Permissions: account.Permissions(),
	}
}

func makeGenesisValidator(validator acm.Validator) genValidator {
	return genValidator{
		PublicKey: validator.PublicKey(),
		Address:   validator.Address(),
		Stake:     validator.Power(),
	}
}

// MakeGenesisDoc takes a chainName and a slice of pointers to Account,
// and a slice of pointers to Validator to construct a GenesisDoc, or returns an error on
// failure.  In particular MakeGenesisDocFromAccount uses the local time as a
// timestamp for the GenesisDoc.
func MakeGenesisDoc(chainName string, salt []byte, genesisTime time.Time, globalPermissions permission.Permissions,
	names map[crypto.Address]string, accounts []*acm.Account, validators []acm.Validator) *GenesisDoc {

	// Establish deterministic order of accounts by address so we obtain identical GenesisDoc
	// from identical input
	sort.SliceStable(accounts, func(i, j int) bool {
		return bytes.Compare(accounts[i].Address().Bytes(), accounts[j].Address().Bytes()) < 0
	})

	sort.SliceStable(validators, func(i, j int) bool {
		return bytes.Compare(validators[i].Address().Bytes(), validators[j].Address().Bytes()) < 0
	})

	// copy slice of pointers to accounts
	genAccounts := make([]genAccount, 0, len(accounts))
	for _, account := range accounts {
		genAccount := makeGenesisAccount(account)
		genAccount.Name = names[genAccount.Address]

		genAccounts = append(genAccounts, genAccount)
	}

	// copy slice of pointers to validators
	genValidators := make([]genValidator, 0, len(validators))
	for _, validator := range validators {
		genValidator := makeGenesisValidator(validator)

		genValidators = append(genValidators, genValidator)
	}

	return &GenesisDoc{
		ChainName:         chainName,
		Salt:              salt,
		GenesisTime:       genesisTime,
		GlobalPermissions: globalPermissions,
		GenAccounts:       genAccounts,
		GenValidators:     genValidators,
	}
}
