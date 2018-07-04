package evm

import (
	acm "github.com/hyperledger/burrow/account"
	"github.com/hyperledger/burrow/crypto"
)

// Create a new account from a parent 'creator' account. The creator account will have its
// sequence number incremented
func DeriveNewAccount(creator *acm.Account) *acm.Account {
	// Generate an address
	sequence := creator.Sequence()
	creator.IncSequence()

	address := crypto.NewContractAddress(creator.Address(), sequence)

	return acm.NewAccount(address)
}
