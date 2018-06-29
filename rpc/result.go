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
	"encoding/json"
	"fmt"

	"time"

	acm "github.com/hyperledger/burrow/account"
	"github.com/hyperledger/burrow/binary"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/execution"
	"github.com/hyperledger/burrow/execution/events"
	"github.com/hyperledger/burrow/execution/events/pbevents"
	"github.com/hyperledger/burrow/execution/names"
	"github.com/hyperledger/burrow/genesis"
	"github.com/hyperledger/burrow/permission"
	"github.com/hyperledger/burrow/txs"
	"github.com/tendermint/go-amino"
	consensusTypes "github.com/tendermint/tendermint/consensus/types"
	"github.com/tendermint/tendermint/p2p"
	"github.com/tendermint/tendermint/rpc/core/types"
	tmTypes "github.com/tendermint/tendermint/types"
)

// When using Tendermint types like Block and Vote we are forced to wrap the outer object and use amino marshalling
var aminoCodec = amino.NewCodec()

func init() {
	//types.RegisterEvidences(AminoCodec)
	//crypto.RegisterAmino(cdc)
	core_types.RegisterAmino(aminoCodec)
}

type ResultGetStorage struct {
	Key   binary.HexBytes
	Value binary.HexBytes
}

type ResultCall struct {
	execution.Call
}

func (rc ResultCall) MarshalJSON() ([]byte, error) {
	return json.Marshal(rc.Call)
}

func (rc *ResultCall) UnmarshalJSON(data []byte) (err error) {
	return json.Unmarshal(data, &rc.Call)
}

type ResultListAccounts struct {
	BlockHeight uint64
	Accounts    []*acm.Account
}

type ResultDumpStorage struct {
	StorageRoot  binary.HexBytes
	StorageItems []StorageItem
}

type StorageItem struct {
	Key   binary.HexBytes
	Value binary.HexBytes
}

type ResultListBlocks struct {
	LastHeight uint64
	BlockMetas []*tmTypes.BlockMeta
}

type ResultGetBlock struct {
	BlockMeta *BlockMeta
	Block     *Block
}

type BlockMeta struct {
	*tmTypes.BlockMeta
}

func (bm BlockMeta) MarshalJSON() ([]byte, error) {
	return aminoCodec.MarshalJSON(bm.BlockMeta)
}

func (bm *BlockMeta) UnmarshalJSON(data []byte) (err error) {
	return aminoCodec.UnmarshalJSON(data, &bm.BlockMeta)
}

// Needed for go-amino handling of interface types
type Block struct {
	*tmTypes.Block
}

func (b Block) MarshalJSON() ([]byte, error) {
	return aminoCodec.MarshalJSON(b.Block)
}

func (b *Block) UnmarshalJSON(data []byte) (err error) {
	return aminoCodec.UnmarshalJSON(data, &b.Block)
}

type ResultStatus struct {
	NodeInfo          p2p.NodeInfo
	GenesisHash       binary.HexBytes
	PubKey            crypto.PublicKey
	LatestBlockHash   binary.HexBytes
	LatestBlockHeight uint64
	LatestBlockTime   int64
	NodeVersion       string
}

type ResultLastBlockInfo struct {
	LastBlockHeight uint64
	LastBlockTime   time.Time
	LastBlockHash   binary.HexBytes
}

type ResultChainId struct {
	ChainName   string
	ChainId     string
	GenesisHash binary.HexBytes
}

type ResultSubscribe struct {
	EventID        string
	SubscriptionID string
}

type ResultUnsubscribe struct {
	SubscriptionID string
}

type Peer struct {
	NodeInfo   p2p.NodeInfo
	IsOutbound bool
}

type ResultNetInfo struct {
	Listening bool
	Listeners []string
	Peers     []*Peer
}

type ResultListValidators struct {
	BlockHeight         uint64
	BondedValidators    []*acm.ConcreteValidator
	UnbondingValidators []*acm.ConcreteValidator
}

type ResultDumpConsensusState struct {
	RoundState      consensusTypes.RoundStateSimple
	PeerRoundStates []*consensusTypes.PeerRoundState
}

type ResultPeers struct {
	Peers []*Peer
}

type ResultListNames struct {
	BlockHeight uint64
	Names       []*names.Entry
}

type ResultGeneratePrivateAccount struct {
	PrivateAccount *acm.ConcretePrivateAccount
}

type ResultGetAccount struct {
	Account *acm.Account
}

type AccountHumanReadable struct {
	Address     crypto.Address
	PublicKey   crypto.PublicKey
	Sequence    uint64
	Balance     uint64
	Code        []string
	StorageRoot string
	Permissions permission.Permissions
}

type ResultGetAccountHumanReadable struct {
	Account *AccountHumanReadable
}

type ResultBroadcastTx struct {
	txs.Receipt
}

func (rbt ResultBroadcastTx) MarshalJSON() ([]byte, error) {
	return json.Marshal(rbt.Receipt)
}

func (rbt ResultBroadcastTx) UnmarshalJSON(data []byte) (err error) {
	return json.Unmarshal(data, &rbt.Receipt)
}

type ResultListUnconfirmedTxs struct {
	NumTxs int
	Txs    []*txs.Envelope
}

type ResultGetName struct {
	Entry *names.Entry
}

type ResultGenesis struct {
	Genesis genesis.GenesisDoc
}

type ResultSignTx struct {
	Tx *txs.Envelope
}

type TendermintEvent struct {
	tmTypes.TMEventData
}

func (te TendermintEvent) MarshalJSON() ([]byte, error) {
	return aminoCodec.MarshalJSON(te.TMEventData)
}

func (te *TendermintEvent) UnmarshalJSON(data []byte) (err error) {
	return aminoCodec.UnmarshalJSON(data, &te.TMEventData)
}

func (te *TendermintEvent) EventDataNewBlock() *tmTypes.EventDataNewBlock {
	if te != nil {
		eventData, _ := te.TMEventData.(tmTypes.EventDataNewBlock)
		return &eventData
	}
	return nil
}

type ResultEvent struct {
	Event      string
	Tendermint *TendermintEvent `json:",omitempty"`
	Execution  *events.Event    `json:",omitempty"`
}

// Map any supported event data element to our ResultEvent sum type
func NewResultEvent(event string, eventData interface{}) (*ResultEvent, error) {
	res := &ResultEvent{
		Event: event,
	}
	switch ed := eventData.(type) {
	case tmTypes.TMEventData:
		res.Tendermint = &TendermintEvent{ed}
	case *events.Event:
		res.Execution = ed
	default:
		return nil, fmt.Errorf("could not map event data of type %T to ResultEvent", eventData)
	}
	return res, nil
}

func (re *ResultEvent) GetEvent() (*pbevents.Event, error) {
	ev := &pbevents.Event{
		Name: re.Event,
	}
	if re.Tendermint != nil {
		bs, err := json.Marshal(re.Tendermint)
		if err != nil {
			return nil, err
		}
		ev.Event = &pbevents.Event_TendermintEventJSON{
			TendermintEventJSON: string(bs),
		}
	} else if re.Execution != nil {
		ev.Event = &pbevents.Event_ExecutionEvent{
			ExecutionEvent: pbevents.GetExecutionEvent(re.Execution),
		}
	} else {
		return nil, fmt.Errorf("ResultEvent is empty")
	}
	return ev, nil
}
