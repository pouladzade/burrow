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

package txs

import (
	"encoding/json"
	"fmt"

	acm "github.com/hyperledger/burrow/account"
	"github.com/hyperledger/burrow/binary"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/txs/payload"
	"golang.org/x/crypto/ripemd160"
)

// Tx is the canonical object that we serialise to produce the SignBytes that we sign
type Tx struct {
	ChainID string
	Payload payload.Payload
	txHash  []byte
}

// Wrap the Payload in Tx required for signing and serialisation
func NewTx(payload payload.Payload) *Tx {
	return &Tx{
		Payload: payload,
	}
}

// Enclose this Tx in an Envelope to be signed
func (tx *Tx) Enclose() *Envelope {
	return &Envelope{
		Tx: *tx,
	}
}

// Encloses in Envelope and signs envelope
func (tx *Tx) Sign(signingAccounts ...acm.AddressableSigner) (*Envelope, error) {
	env := tx.Enclose()
	err := env.Sign(signingAccounts...)
	if err != nil {
		return nil, err
	}
	return env, nil
}

// Generate SignBytes, panicking on any failure
func (tx *Tx) MustSignBytes() []byte {
	bs, err := tx.SignBytes()
	if err != nil {
		panic(err)
	}
	return bs
}

// Produces the canonical SignBytes (the Tx message that will be signed) for a Tx
func (tx *Tx) SignBytes() ([]byte, error) {
	bs, err := json.Marshal(tx)
	if err != nil {
		return nil, fmt.Errorf("could not generate canonical SignBytes for Payload %v: %v", tx.Payload, err)
	}
	return bs, nil
}

// Serialisation intermediate for switching on type
type wrapper struct {
	ChainID string
	Type    payload.Type
	Payload json.RawMessage
}

func (tx *Tx) MarshalJSON() ([]byte, error) {
	bs, err := json.Marshal(tx.Payload)
	if err != nil {
		return nil, err
	}
	return json.Marshal(wrapper{
		ChainID: tx.ChainID,
		Type:    tx.Payload.Type(),
		Payload: bs,
	})
}

func (tx *Tx) UnmarshalJSON(data []byte) error {
	w := new(wrapper)
	err := json.Unmarshal(data, w)
	if err != nil {
		return err
	}
	tx.ChainID = w.ChainID
	// Now we know the Type we can deserialise the Payload
	tx.Payload = payload.New(w.Type)
	return json.Unmarshal(w.Payload, tx.Payload)
}

func (tx *Tx) Type() payload.Type {
	if tx == nil {
		return payload.TypeUnknown
	}
	return tx.Payload.Type()
}

// Generate a Hash for this transaction based on the SignBytes. The hash is memoized over the lifetime
// of the Tx so repeated calls to Hash() are effectively free
func (tx *Tx) Hash() []byte {
	if tx == nil {
		return nil
	}
	if tx.txHash == nil {
		return tx.Rehash()
	}
	return tx.txHash
}

func (tx *Tx) String() string {
	if tx == nil {
		return "Tx{nil}"
	}
	return fmt.Sprintf("Tx{TxHash: %X; Payload: %v}", tx.Hash(), tx.Payload)
}

// Regenerate the Tx hash if it has been mutated or as called by Hash() in first instance
func (tx *Tx) Rehash() []byte {
	hasher := ripemd160.New()
	hasher.Write(tx.MustSignBytes())
	tx.txHash = hasher.Sum(nil)
	return tx.txHash
}

// BroadcastTx or Transaction receipt
type Receipt struct {
	TxHash          binary.HexBytes
	CreatesContract bool
	ContractAddress crypto.Address
}

// Generate a transaction Receipt containing the Tx hash and other information if the Tx is call.
// Returned by ABCI methods.
func (tx *Tx) GenerateReceipt() *Receipt {
	receipt := &Receipt{
		TxHash: tx.Hash(),
	}
	if callTx, ok := tx.Payload.(*payload.CallTx); ok {
		receipt.CreatesContract = callTx.CreatesContract()
		if receipt.CreatesContract {
			receipt.ContractAddress = crypto.NewContractAddress(callTx.Caller(), callTx.Sequence())
		} else {
			receipt.ContractAddress = callTx.Callee()
		}
	}
	return receipt
}
