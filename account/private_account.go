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
	"fmt"

	"github.com/hyperledger/burrow/crypto"
)

type AddressableSigner interface {
	crypto.Signer
	Address() crypto.Address
	PublicKey() crypto.PublicKey
}

type PrivateAccount interface {
	AddressableSigner
	PrivateKey() crypto.PrivateKey
}

//
type ConcretePrivateAccount struct {
	PrivateKey crypto.PrivateKey
}

type concretePrivateAccountWrapper struct {
	*ConcretePrivateAccount `json:"unwrap"`
}

var _ PrivateAccount = concretePrivateAccountWrapper{}

func AsConcretePrivateAccount(privateAccount PrivateAccount) *ConcretePrivateAccount {
	if privateAccount == nil {
		return nil
	}
	// Avoid a copy
	if ca, ok := privateAccount.(concretePrivateAccountWrapper); ok {
		return ca.ConcretePrivateAccount
	}
	return &ConcretePrivateAccount{
		PrivateKey: privateAccount.PrivateKey(),
	}
}

func (cpaw concretePrivateAccountWrapper) Address() crypto.Address {
	return cpaw.PublicKey().Address()
}

func (cpaw concretePrivateAccountWrapper) PublicKey() crypto.PublicKey {
	return cpaw.PrivateKey().GetPublicKey()
}

func (cpaw concretePrivateAccountWrapper) PrivateKey() crypto.PrivateKey {
	return cpaw.ConcretePrivateAccount.PrivateKey
}

func (cpaw concretePrivateAccountWrapper) String() string {
	return cpaw.ConcretePrivateAccount.String()
}

// ConcretePrivateAccount

func (pa ConcretePrivateAccount) PrivateAccount() PrivateAccount {
	return concretePrivateAccountWrapper{ConcretePrivateAccount: &pa}
}

func (pa ConcretePrivateAccount) Sign(msg []byte) (crypto.Signature, error) {
	return pa.PrivateKey.Sign(msg)
}

func (pa *ConcretePrivateAccount) String() string {
	return fmt.Sprintf("ConcretePrivateAccount{%s}", pa.PrivateAccount().Address())
}

// Convert slice of ConcretePrivateAccounts to slice of SigningAccounts
func SigningAccounts(concretePrivateAccounts []*ConcretePrivateAccount) []AddressableSigner {
	signingAccounts := make([]AddressableSigner, len(concretePrivateAccounts))
	for i, cpa := range concretePrivateAccounts {
		signingAccounts[i] = cpa.PrivateAccount()
	}
	return signingAccounts
}

// Generates a new account with private key.
func GeneratePrivateAccount() (PrivateAccount, error) {
	privateKey, err := crypto.GeneratePrivateKey(nil, crypto.CurveTypeEd25519)
	if err != nil {
		return nil, err
	}
	return ConcretePrivateAccount{
		PrivateKey: privateKey,
	}.PrivateAccount(), nil
}

// Generates a new account with private key from SHA256 hash of a secret
func GeneratePrivateAccountFromSecret(secret string) PrivateAccount {
	privateKey := crypto.PrivateKeyFromSecret(secret, crypto.CurveTypeEd25519)
	return ConcretePrivateAccount{
		PrivateKey: privateKey,
	}.PrivateAccount()
}

func GeneratePrivateAccountFromPrivateKeyBytes(privKeyBytes []byte) (PrivateAccount, error) {
	privateKey, err := crypto.PrivateKeyFromRawBytes(privKeyBytes, crypto.CurveTypeEd25519)
	if err != nil {
		return nil, err
	}
	return ConcretePrivateAccount{
		PrivateKey: privateKey,
	}.PrivateAccount(), nil
}
