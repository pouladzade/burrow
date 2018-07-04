package executors

import (
	"github.com/hyperledger/burrow/errors"

	acm "github.com/hyperledger/burrow/account"
	"github.com/hyperledger/burrow/account/state"
	"github.com/hyperledger/burrow/blockchain"
	"github.com/hyperledger/burrow/event"
	"github.com/hyperledger/burrow/execution/events"
	"github.com/hyperledger/burrow/logging"
	"github.com/hyperledger/burrow/permission"
	"github.com/hyperledger/burrow/txs"
	"github.com/hyperledger/burrow/txs/payload"
	"github.com/hyperledger/burrow/util"
)

type SendContext struct {
	Tip            blockchain.TipInfo
	StateWriter    state.ReaderWriter
	EventPublisher event.Publisher
	Logger         *logging.Logger
	txEnv          *txs.Envelope
}

func (ctx *SendContext) Execute(txEnv *txs.Envelope) error {
	tx, ok := txEnv.Tx.Payload.(*payload.SendTx)
	if !ok {
		return e.Error(e.ErrTxWrongPayload)
	}
	ctx.txEnv = txEnv

	accounts, err := checkTx(ctx.StateWriter, tx, permission.Send)
	if err != nil {
		return err
	}

	for _, output := range tx.Outputs() {
		if accounts[output.Address] == nil {
			/// check for CreateAccount permission
			for _, input := range tx.Inputs() {
				account := accounts[input.Address]
				if !util.HasCreateAccountPermission(ctx.StateWriter, account) {
					return e.Errorf(e.ErrPermDenied, "%s has %s but needs %s", account.Address(), account.Permissions(), permission.CreateAccount)
				}
			}
		}
	}

	/// Create accounts
	for _, output := range tx.Outputs() {
		if accounts[output.Address] == nil {
			accounts[output.Address] = acm.NewAccount(output.Address)
		}
	}

	// Good! Adjust accounts
	err = adjustByInputs(accounts, tx.Inputs())
	if err != nil {
		return err
	}

	err = adjustByOutputs(accounts, tx.Outputs())
	if err != nil {
		return err
	}

	for _, account := range accounts {
		ctx.StateWriter.UpdateAccount(account)
	}

	if ctx.EventPublisher != nil {
		for _, i := range tx.Inputs() {
			events.PublishAccountInput(ctx.EventPublisher, ctx.Tip.LastBlockHeight(), i.Address, &txEnv.Tx, nil, nil)
		}

		for _, o := range tx.Outputs() {
			events.PublishAccountOutput(ctx.EventPublisher, ctx.Tip.LastBlockHeight(), o.Address, &txEnv.Tx, nil, nil)
		}
	}
	return nil
}
