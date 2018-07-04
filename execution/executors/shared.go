package executors

import (
	acm "github.com/hyperledger/burrow/account"
	"github.com/hyperledger/burrow/account/state"
	"github.com/hyperledger/burrow/crypto"
	e "github.com/hyperledger/burrow/errors"
	"github.com/hyperledger/burrow/permission"
	"github.com/hyperledger/burrow/txs/payload"
	"github.com/hyperledger/burrow/util"
)

func checkTx(getter state.AccountGetter, tx payload.Payload, requiredPermissions permission.Permissions) (
	accounts map[crypto.Address]*acm.Account, err error) {

	accounts = make(map[crypto.Address]*acm.Account)
	inputs := tx.Inputs()
	outputs := tx.Outputs()
	inAmount := uint64(0)
	outAmount := uint64(0)
	for _, input := range inputs {
		// Check TxInput basic
		if err := input.ValidateBasic(); err != nil {
			return nil, err
		}

		account, err := getter.GetAccount(input.Address)
		if err != nil {
			return nil, err
		}

		if !util.HasPermissions(getter, account, requiredPermissions) {
			return nil, e.Errorf(e.ErrPermDenied, "%s has %s but needs %s", account.Address(), account.Permissions(), requiredPermissions)

		}

		// Check sequences
		if account.Sequence()+1 != uint64(input.Sequence) {
			return nil, e.Errorf(e.ErrTxInvalidSequence, "%s has set sequence to %s. It should be %s", input.Address, input.Sequence, account.Sequence()+uint64(1))
		}

		// Check amount
		if account.Balance() < uint64(input.Amount) {
			return nil, e.Error(e.ErrTxInsufficientFunds)
		}

		// Account shouldn't be duplicated
		if _, ok := accounts[input.Address]; ok {
			return nil, e.Error(e.ErrTxDuplicateAddress)
		}

		accounts[input.Address] = account
		inAmount += input.Amount
	}

	for _, output := range outputs {
		// Check TxOutput basic
		if err := output.ValidateBasic(); err != nil {
			return nil, err
		}

		account, err := getter.GetAccount(output.Address)
		if err != nil {
			return nil, err
		}

		// Account shouldn't be duplicated
		if _, ok := accounts[output.Address]; ok {
			return nil, e.Error(e.ErrTxDuplicateAddress)
		}

		accounts[output.Address] = account
		outAmount += output.Amount
	}

	if inAmount < outAmount {
		return nil, e.Error(e.ErrTxInsufficientFunds)
	}

	return accounts, nil
}

func adjustByInputs(accounts map[crypto.Address]*acm.Account, inputs []payload.TxInput) error {
	for _, input := range inputs {
		account := accounts[input.Address]
		if account == nil {
			return e.Error(e.ErrTxInvalidAddress)
		}

		if account.Balance() < input.Amount {
			return e.Error(e.ErrTxInsufficientFunds)
		}

		err := account.SubtractFromBalance(input.Amount)
		if err != nil {
			return err
		}

		account.IncSequence()
	}
	return nil
}

func adjustByOutputs(accounts map[crypto.Address]*acm.Account, outputs []payload.TxOutput) error {
	for _, output := range outputs {
		account := accounts[output.Address]
		if account == nil {
			return e.Error(e.ErrTxInvalidAddress)
		}

		err := account.AddToBalance(output.Amount)
		if err != nil {
			return err
		}
	}
	return nil
}
