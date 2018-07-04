package executors

import (
	"fmt"
	acm "github.com/hyperledger/burrow/account"
	"github.com/hyperledger/burrow/account/state"
	"github.com/hyperledger/burrow/binary"
	"github.com/hyperledger/burrow/blockchain"
	"github.com/hyperledger/burrow/event"
	"github.com/hyperledger/burrow/execution/errors"
	"github.com/hyperledger/burrow/execution/events"
	"github.com/hyperledger/burrow/execution/evm"
	"github.com/hyperledger/burrow/logging"
	"github.com/hyperledger/burrow/logging/structure"
	"github.com/hyperledger/burrow/permission"
	"github.com/hyperledger/burrow/txs"
	"github.com/hyperledger/burrow/txs/payload"
)

// TODO: make configurable
const GasLimit = uint64(1000000)

type CallContext struct {
	Tip            blockchain.TipInfo
	StateWriter    state.ReaderWriter
	EventPublisher event.Publisher
	RunCall        bool
	VMOptions      []func(*evm.VM)
	Logger         *logging.Logger
	txEnv          *txs.Envelope
}

func (ctx *CallContext) Execute(txEnv *txs.Envelope) error {
	tx, ok := txEnv.Tx.Payload.(*payload.CallTx)
	if !ok {
		return fmt.Errorf("payload must be CallTx, but is: %v", txEnv.Tx.Payload)
	}
	ctx.txEnv = txEnv

	var requiredPermissions permission.Permissions
	var caller, callee *acm.Account

	if tx.CreatesContract() {
		requiredPermissions = permission.CreateContract
	} else {
		requiredPermissions = permission.Call
	}

	accounts, err := checkTx(ctx.StateWriter, tx, requiredPermissions)
	if err != nil {
		return err
	}
	caller, ok = accounts[tx.Caller()]
	callee, ok = accounts[tx.Callee()]

	err = caller.SubtractFromBalance(tx.Fee())
	if err != nil {
		return err
	}
	ctx.StateWriter.UpdateAccount(caller)

	if tx.CreatesContract() {
		caller.IncSequence()
	} else {
		// check if its a native contract
		if evm.IsRegisteredNativeContract(tx.Callee().Word256()) {
			return fmt.Errorf("attempt to call a native contract at %s, "+
				"but native contracts cannot be called using CallTx. Use a "+
				"contract that calls the native contract or the appropriate tx "+
				"type (eg. PermissionsTx, NameTx)", tx.Callee())
		}

		if callee == nil {
			// Output account may be nil if we are still in mempool and contract was created in same block as this tx
			// but that's fine, because the account will be created properly when the create tx runs in the block
			// and then this won't return nil. otherwise, we take their fee
			// Note: ctx.tx.Address == nil if createContract so dereference is okay
		}
	}

	if ctx.RunCall {
		ctx.Deliver(tx, caller, callee)
	} else {
		// The mempool does not call txs until
		// the proposer determines the order of txs.
		// So mempool will skip the actual .Call(),
		// and only deduct from the caller's balance.

		err = caller.SubtractFromBalance(tx.Amount())
		if err != nil {
			return err
		}
		ctx.StateWriter.UpdateAccount(caller)
	}

	return nil
}

func (ctx *CallContext) Deliver(tx *payload.CallTx, caller, callee *acm.Account) error {
	createContract := tx.CreatesContract()
	// VM call variables
	var (
		gas     uint64 = tx.GasLimit()
		code    []byte = nil
		ret     []byte = nil
		txCache        = state.NewCache(ctx.StateWriter, state.Name("TxCache"))
		params         = evm.Params{
			BlockHeight: ctx.Tip.LastBlockHeight(),
			BlockHash:   binary.LeftPadWord256(ctx.Tip.LastBlockHash()),
			BlockTime:   ctx.Tip.LastBlockTime().Unix(),
			GasLimit:    GasLimit,
		}
	)

	// get or create callee
	if createContract {
		// We already checked for permission
		callee = evm.DeriveNewAccount(caller)
		code = tx.Data()
		ctx.Logger.TraceMsg("Creating new contract",
			"contract_address", callee.Address(),
			"init_code", code)
	} else {
		if callee == nil || len(callee.Code()) == 0 {
			// if you call an account that doesn't exist
			// or an account with no code then we take fees (sorry pal)
			// NOTE: it's fine to create a contract and call it within one
			// block (sequence number will prevent re-ordering of those txs)
			// but to create with one contract and call with another
			// you have to wait a block to avoid a re-ordering attack
			// that will take your fees
			if callee == nil {
				ctx.Logger.InfoMsg("Call to address that does not exist",
					"caller_address", tx.Caller(),
					"callee_address", tx.Callee())
			} else {
				ctx.Logger.InfoMsg("Call to address that holds no code",
					"caller_address", tx.Caller(),
					"callee_address", tx.Callee())
			}
			ctx.FireCallEvents(tx, nil, errors.ErrorCodeUnknownAddress)
			return nil
		}
		code = callee.Code()
		ctx.Logger.TraceMsg("Calling existing contract",
			"contract_address", callee.Address(),
			"input", tx.Data(),
			"contract_code", code)
	}
	ctx.Logger.Trace.Log("callee", callee.Address().String())

	txCache.UpdateAccount(caller)
	txCache.UpdateAccount(callee)
	vmach := evm.NewVM(params, caller.Address(), &ctx.txEnv.Tx, ctx.Logger, ctx.VMOptions...)
	vmach.SetPublisher(ctx.EventPublisher)
	// NOTE: Call() transfers the value from caller to callee iff call succeeds.
	ret, err := vmach.Call(txCache, caller, callee, code, tx.Data(), tx.Amount(), &gas)
	if err != nil {
		// Failure. Charge the gas fee. The 'value' was otherwise not transferred.
		ctx.Logger.InfoMsg("Error on execution",
			structure.ErrorKey, err)
	} else {
		ctx.Logger.TraceMsg("Successful execution")
		if createContract {
			callee.SetCode(ret)
		}
		// Update caller/callee to txCache.
		txCache.UpdateAccount(caller)
		txCache.UpdateAccount(callee)

		err := txCache.Sync(ctx.StateWriter)
		if err != nil {
			return err
		}
	}
	// Create a receipt from the ret and whether it erred.
	ctx.Logger.TraceMsg("VM call complete",
		"caller", caller,
		"callee", callee,
		"return", ret,
		structure.ErrorKey, err)
	ctx.FireCallEvents(tx, ret, err)
	return nil
}

func (ctx *CallContext) FireCallEvents(tx *payload.CallTx, ret []byte, err error) {
	// Fire Events for sender and receiver
	// a separate event will be fired from vm for each additional call
	if ctx.EventPublisher != nil {
		events.PublishAccountInput(ctx.EventPublisher, ctx.Tip.LastBlockHeight(), tx.Caller(), &ctx.txEnv.Tx, ret, errors.AsCodedError(err))
		if tx.CreatesContract() {
			events.PublishAccountOutput(ctx.EventPublisher, ctx.Tip.LastBlockHeight(), tx.Callee(), &ctx.txEnv.Tx, ret, errors.AsCodedError(err))
		}
	}
}
