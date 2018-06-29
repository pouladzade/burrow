package executors

import (
	"fmt"

	"github.com/hyperledger/burrow/account/state"
	"github.com/hyperledger/burrow/blockchain"
	"github.com/hyperledger/burrow/event"
	"github.com/hyperledger/burrow/execution/events"
	"github.com/hyperledger/burrow/logging"
	"github.com/hyperledger/burrow/txs"
	"github.com/hyperledger/burrow/txs/payload"
	"github.com/hyperledger/burrow/util"
)

type SendContext struct {
	Tip            blockchain.TipInfo
	StateWriter    state.ReaderWriter
	EventPublisher event.Publisher
	Logger         *logging.Logger
	tx             *payload.SendTx
}

func (ctx *SendContext) Execute(txEnv *txs.Envelope) error {
	var ok bool
	ctx.tx, ok = txEnv.Tx.Payload.(*payload.SendTx)
	if !ok {
		return fmt.Errorf("payload must be NameTx, but is: %v", txEnv.Tx.Payload)
	}
	accounts, err := getInputs(ctx.StateWriter, ctx.tx.Inputs)
	if err != nil {
		return err
	}

	// ensure all inputs have send permissions
	if !util.HaveSendPermission(ctx.StateWriter, accounts) {
		return fmt.Errorf("at least one input lacks permission for SendTx")
	}

	// add outputs to accounts map
	// if any outputs don't exist, all inputs must have CreateAccount perm
	accounts, err = getOrMakeOutputs(ctx.StateWriter, accounts, ctx.tx.Outputs, ctx.Logger)
	if err != nil {
		return err
	}

	inTotal, err := validateInputs(accounts, ctx.tx.Inputs)
	if err != nil {
		return err
	}
	outTotal, err := validateOutputs(ctx.tx.Outputs)
	if err != nil {
		return err
	}
	if outTotal > inTotal {
		return payload.ErrTxInsufficientFunds
	}

	// Good! Adjust accounts
	err = adjustByInputs(accounts, ctx.tx.Inputs, ctx.Logger)
	if err != nil {
		return err
	}

	err = adjustByOutputs(accounts, ctx.tx.Outputs)
	if err != nil {
		return err
	}

	for _, acc := range accounts {
		ctx.StateWriter.UpdateAccount(acc)
	}

	if ctx.EventPublisher != nil {
		for _, i := range ctx.tx.Inputs {
			events.PublishAccountInput(ctx.EventPublisher, ctx.Tip.LastBlockHeight(), i.Address, txEnv.Tx, nil, nil)
		}

		for _, o := range ctx.tx.Outputs {
			events.PublishAccountOutput(ctx.EventPublisher, ctx.Tip.LastBlockHeight(), o.Address, txEnv.Tx, nil, nil)
		}
	}
	return nil
}
