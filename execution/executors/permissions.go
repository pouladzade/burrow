package executors

import (
	"github.com/hyperledger/burrow/account/state"
	"github.com/hyperledger/burrow/blockchain"
	"github.com/hyperledger/burrow/errors"
	"github.com/hyperledger/burrow/event"
	"github.com/hyperledger/burrow/execution/events"
	"github.com/hyperledger/burrow/logging"
	"github.com/hyperledger/burrow/permission"
	"github.com/hyperledger/burrow/txs"
	"github.com/hyperledger/burrow/txs/payload"
)

type PermissionsContext struct {
	Tip            blockchain.TipInfo
	StateWriter    state.ReaderWriter
	EventPublisher event.Publisher
	Logger         *logging.Logger
	txEnv          *txs.Envelope
}

func (ctx *PermissionsContext) Execute(txEnv *txs.Envelope) error {
	tx, ok := txEnv.Tx.Payload.(*payload.PermissionsTx)
	if !ok {
		return e.Error(e.ErrTxWrongPayload)
	}
	ctx.txEnv = txEnv

	requiredPermissions := permission.ModifyPermission
	accounts, err := checkTx(ctx.StateWriter, tx, requiredPermissions)
	if err != nil {
		return err
	}

	modifier := accounts[tx.Modifier()]
	modified := accounts[tx.Modified()]
	if modified == nil {
		return e.Error(e.ErrTxInvalidAddress)
	}

	if tx.Set() {
		modified.SetPermissions(tx.Permissions())
	} else {
		modified.UnsetPermissions(tx.Permissions())
	}

	adjustByInputs(accounts, tx.Inputs())

	err = ctx.StateWriter.UpdateAccount(modifier)
	if err != nil {
		return err
	}

	err = ctx.StateWriter.UpdateAccount(modified)
	if err != nil {
		return err
	}

	if ctx.EventPublisher != nil {
		events.PublishAccountInput(ctx.EventPublisher, ctx.Tip.LastBlockHeight(), tx.Modifier(), &txEnv.Tx, nil, nil)
		events.PublishPermissions(ctx.EventPublisher, ctx.Tip.LastBlockHeight(), &txEnv.Tx)
	}
	return nil

}
