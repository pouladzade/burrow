package executors

import (
	"fmt"

	acm "github.com/hyperledger/burrow/account"
	"github.com/hyperledger/burrow/account/state"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/logging"
	"github.com/hyperledger/burrow/permission"
	"github.com/hyperledger/burrow/txs/payload"
	"github.com/hyperledger/burrow/util"
)

// The accounts from the TxInputs must either already have
// acm.PublicKey().(type) != nil, (it must be known),
// or it must be specified in the TxInput.  If redeclared,
// the TxInput is modified and input.PublicKey() set to nil.
func getInputs(accountGetter state.AccountGetter,
	ins []*payload.TxInput) (map[crypto.Address]*acm.Account, error) {

	accounts := map[crypto.Address]*acm.Account{}
	for _, in := range ins {
		// Account shouldn't be duplicated
		if _, ok := accounts[in.Address]; ok {
			return nil, payload.ErrTxDuplicateAddress
		}
		acc, err := state.GetAccount(accountGetter, in.Address)
		if err != nil {
			return nil, err
		}
		if acc == nil {
			return nil, payload.ErrTxInvalidAddress
		}
		accounts[in.Address] = acc
	}
	return accounts, nil
}

func getOrMakeOutputs(accountGetter state.AccountGetter, accs map[crypto.Address]*acm.Account,
	outs []*payload.TxOutput, logger *logging.Logger) (map[crypto.Address]*acm.Account, error) {
	if accs == nil {
		accs = make(map[crypto.Address]*acm.Account)
	}

	// we should err if an account is being created but the inputs don't have permission
	var checkedCreatePerms bool
	for _, out := range outs {
		// Account shouldn't be duplicated
		if _, ok := accs[out.Address]; ok {
			return nil, payload.ErrTxDuplicateAddress
		}
		acc, err := state.GetAccount(accountGetter, out.Address)
		if err != nil {
			return nil, err
		}
		// output account may be nil (new)
		if acc == nil {
			if !checkedCreatePerms {
				if !util.HaveCreateAccountPermission(accountGetter, accs) {
					return nil, fmt.Errorf("at least one input does not have permission to create accounts")
				}
				checkedCreatePerms = true
			}
			acc = acm.NewContractAccount(out.Address, permission.ZeroAccountPermissions)
		}
		accs[out.Address] = acc
	}
	return accs, nil
}

func validateInputs(accs map[crypto.Address]*acm.Account, ins []*payload.TxInput) (uint64, error) {
	total := uint64(0)
	for _, in := range ins {
		acc := accs[in.Address]
		if acc == nil {
			return 0, fmt.Errorf("validateInputs() expects account in accounts, but account %s not found", in.Address)
		}
		err := validateInput(acc, in)
		if err != nil {
			return 0, err
		}
		// Good. Add amount to total
		total += in.Amount
	}
	return total, nil
}

func validateInput(acc *acm.Account, in *payload.TxInput) error {
	// Check TxInput basic
	if err := in.ValidateBasic(); err != nil {
		return err
	}
	// Check sequences
	if acc.Sequence()+1 != uint64(in.Sequence) {
		return payload.ErrTxInvalidSequence{
			Got:      in.Sequence,
			Expected: acc.Sequence() + uint64(1),
		}
	}
	// Check amount
	if acc.Balance() < uint64(in.Amount) {
		return payload.ErrTxInsufficientFunds
	}
	return nil
}

func validateOutputs(outs []*payload.TxOutput) (uint64, error) {
	total := uint64(0)
	for _, out := range outs {
		// Check TxOutput basic
		if err := out.ValidateBasic(); err != nil {
			return 0, err
		}
		// Good. Add amount to total
		total += out.Amount
	}
	return total, nil
}

func adjustByInputs(accs map[crypto.Address]*acm.Account, ins []*payload.TxInput, logger *logging.Logger) error {
	for _, in := range ins {
		acc := accs[in.Address]
		if acc == nil {
			return fmt.Errorf("adjustByInputs() expects account in accounts, but account %s not found", in.Address)
		}
		if acc.Balance() < in.Amount {
			panic("adjustByInputs() expects sufficient funds")
			return fmt.Errorf("adjustByInputs() expects sufficient funds but account %s only has balance %v and "+
				"we are deducting %v", in.Address, acc.Balance(), in.Amount)
		}
		err := acc.SubtractFromBalance(in.Amount)
		if err != nil {
			return err
		}
		logger.TraceMsg("Incrementing sequence number for SendTx (adjustByInputs)",
			"tag", "sequence",
			"account", acc.Address(),
			"old_sequence", acc.Sequence(),
			"new_sequence", acc.Sequence()+1)
		acc.IncSequence()
	}
	return nil
}

func adjustByOutputs(accs map[crypto.Address]*acm.Account, outs []*payload.TxOutput) error {
	for _, out := range outs {
		acc := accs[out.Address]
		if acc == nil {
			return fmt.Errorf("adjustByOutputs() expects account in accounts, but account %s not found",
				out.Address)
		}
		err := acc.AddToBalance(out.Amount)
		if err != nil {
			return err
		}
	}
	return nil
}
