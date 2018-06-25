package executors

import (
	"fmt"

	"github.com/hyperledger/burrow/account/state"
	"github.com/hyperledger/burrow/blockchain"
	"github.com/hyperledger/burrow/event"
	"github.com/hyperledger/burrow/execution/events"
	"github.com/hyperledger/burrow/logging"
	"github.com/hyperledger/burrow/logging/structure"
	"github.com/hyperledger/burrow/txs"
	"github.com/hyperledger/burrow/txs/payload"
	"github.com/hyperledger/burrow/util"
)

type PermissionsContext struct {
	Tip            blockchain.TipInfo
	StateWriter    state.ReaderWriter
	EventPublisher event.Publisher
	Logger         *logging.Logger
	tx             *payload.PermissionsTx
}

func (ctx *PermissionsContext) Execute(txEnv *txs.Envelope) error {
	var ok bool
	ctx.tx, ok = txEnv.Tx.Payload.(*payload.PermissionsTx)
	if !ok {
		return fmt.Errorf("payload must be PermissionsTx, but is: %v", txEnv.Tx.Payload)
	}
	// Validate input
	modifier, err := state.GetAccount(ctx.StateWriter, ctx.tx.Modifier.Address)
	if err != nil {
		return err
	}

	err = ctx.tx.Permissions.EnsureValid()
	if err != nil {
		return err
	}

	if !util.HasModifyPermission(ctx.StateWriter, modifier) {
		return fmt.Errorf("account %s does not have required permission", modifier.Address())
	}

	err = validateInput(modifier, &ctx.tx.Modifier)
	if err != nil {
		ctx.Logger.InfoMsg("validateInput failed",
			"modifier", ctx.tx.Modifier,
			structure.ErrorKey, err)
		return err
	}

	modified, err := state.GetAccount(ctx.StateWriter, ctx.tx.Modified)
	if err != nil {
		return err
	}

	// Good! Adjust accounts
	// Good!
	ctx.Logger.TraceMsg("Incrementing sequence number for PermissionsTx",
		"tag", "sequence",
		"account", modifier.Address(),
		"old_sequence", modifier.Sequence(),
		"new_sequence", modifier.Sequence()+1)

	//// TODO: fees += tx.Modifier.Amount
	modifier.IncSequence()
	/*
		err = adjustByInput(modifier, ctx.tx.Modifier, logger)
		if err != nil {
			return err
		}
	*/

	err = ctx.StateWriter.UpdateAccount(modifier)
	if err != nil {
		return err
	}

	if ctx.tx.Set {
		modified.SetPermissions(ctx.tx.Permissions)
	} else {
		modified.UnsetPermissions(ctx.tx.Permissions)
	}

	err = ctx.StateWriter.UpdateAccount(modified)
	if err != nil {
		return err
	}

	if ctx.EventPublisher != nil {
		events.PublishAccountInput(ctx.EventPublisher, ctx.Tip.LastBlockHeight(), ctx.tx.Modifier.Address, txEnv.Tx, nil, nil)
		events.PublishPermissions(ctx.EventPublisher, ctx.Tip.LastBlockHeight(), txEnv.Tx)
	}
	return nil

}
