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

package rpc

import (
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/hyperledger/burrow/client"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/keys"
	"github.com/hyperledger/burrow/txs"
)

//------------------------------------------------------------------------------------
// sign and broadcast convenience

// tx has either one input or we default to the first one (ie for send/bond)
// TODO: better support for multisig and bonding
func signTx(keyClient keys.KeyClient, tx *txs.Tx) (crypto.Address, *txs.Envelope, error) {
	txEnv := tx.Enclose()
	inputs := tx.Payload.Inputs()
	signer, err := keys.AddressableSigner(keyClient, inputs[0].Address)
	if err != nil {
		return crypto.ZeroAddress, nil, err
	}
	err = txEnv.Sign(signer)
	if err != nil {
		return crypto.ZeroAddress, nil, err
	}
	return signer.Address(), txEnv, nil
}

func checkCommon(nodeClient client.NodeClient, keyClient keys.KeyClient, pubkey, addr, amtS,
	sequenceS string) (pub crypto.PublicKey, amt uint64, sequence uint64, err error) {

	if amtS == "" {
		err = fmt.Errorf("input must specify an amount with the --amt flag")
		return
	}

	if pubkey == "" && addr == "" {
		err = fmt.Errorf("at least one of --pubkey or --addr must be given")
		return
	} else if pubkey != "" {
		if addr != "" {
			nodeClient.Logger().InfoMsg("Both a public key and an address have been specified. The public key takes precedent.",
				"public_key", pubkey,
				"address", addr,
			)
		}
		var pubKeyBytes []byte
		pubKeyBytes, err = hex.DecodeString(pubkey)
		if err != nil {
			err = fmt.Errorf("pubkey is bad hex: %v", err)
			return
		}
		pub, err = crypto.PublicKeyFromBytes(pubKeyBytes, crypto.CurveTypeEd25519)
		if err != nil {
			return
		}
	} else {
		// grab the pubkey from monax-keys
		addressBytes, err2 := hex.DecodeString(addr)
		if err2 != nil {
			err = fmt.Errorf("Bad hex string for address (%s): %v", addr, err)
			return
		}
		address, err2 := crypto.AddressFromBytes(addressBytes)
		if err2 != nil {
			err = fmt.Errorf("Could not convert bytes (%X) to address: %v", addressBytes, err2)
		}
		pub, err2 = keyClient.PublicKey(address)
		if err2 != nil {
			err = fmt.Errorf("Failed to fetch pubkey for address (%s): %v", addr, err2)
			return
		}
	}

	var address crypto.Address
	address = pub.Address()

	amt, err = strconv.ParseUint(amtS, 10, 64)
	if err != nil {
		err = fmt.Errorf("amt is misformatted: %v", err)
	}

	if sequenceS == "" {
		if nodeClient == nil {
			err = fmt.Errorf("input must specify a sequence with the --sequence flag or use --node-addr (or BURROW_CLIENT_NODE_ADDR) to fetch the sequence from a node")
			return
		}
		// fetch sequence from node
		account, err2 := nodeClient.GetAccount(address)
		if err2 != nil {
			return pub, amt, sequence, err2
		}
		sequence = account.Sequence() + 1
		nodeClient.Logger().TraceMsg("Fetch sequence from node",
			"sequence", sequence,
			"account address", address,
		)
	} else {
		sequence, err = strconv.ParseUint(sequenceS, 10, 64)
		if err != nil {
			err = fmt.Errorf("sequence is misformatted: %v", err)
			return
		}
	}

	return
}
