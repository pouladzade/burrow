package permission

import (
	"fmt"

	"github.com/hyperledger/burrow/errors"
)

type Permissions uint64

//------------------------------------------------------------------------------------------------

// Base permission references are like unix (the index is already bit shifted)
const (
	// Send permits an account to issue a SendTx to transfer value from one account to another. Note that value can
	// still be transferred with a CallTx by specifying an Amount in the InputTx. Funding an account is the basic
	// prerequisite for an account to act in the system so is often used as a surrogate for 'account creation' when
	// sending to a unknown account - in order for this to be permitted the input account needs the CreateAccount
	// permission in addition.
	Send Permissions = 1 << iota // 0x0001
	// Call permits and account to issue a CallTx, which can be used to call (run) the code of an existing
	// account/contract (these are synonymous in Burrow/EVM). A CallTx can be used to create an account if it points to
	// a nil address - in order for an account to be permitted to do this the input (calling) account needs the
	// CreateContract permission in addition.
	Call // 0x0002
	// CreateContract permits the input account of a CallTx to create a new contract/account when CallTx.Address is nil
	// and permits an executing contract in the EVM to create a new contract programmatically.
	CreateContract // 0x0004
	// CreateAccount permits an input account of a SendTx to add value to non-existing (unfunded) accounts
	CreateAccount // 0x0008
	// Bond is a reserved permission for making changes to the validator set - currently unused
	Bond // 0x0010
	// Name permits manipulation of the name registry by allowing an account to issue a NameTx
	Name // 0x0020
	//
	ModifyPermission // 0x0040
	//
	CreateChain // 0x0080
	//
	InterChainTx // 0x0100

	Reserved
)

var (
	ZeroPermissions    Permissions
	DefaultPermissions Permissions = Call | Send | CreateAccount | CreateContract
)

func (p Permissions) EnsureValid() error {
	allPermissions := (Reserved - 1)

	if (p & ^allPermissions) != 0 {
		return e.Errorf(e.ErrPermInvalid, "%x", p)
	}
	return nil
}

func (p *Permissions) Set(r Permissions) {
	*p |= r
}

func (p *Permissions) Unset(r Permissions) {
	*p &= ^r
}

func (p Permissions) IsSet(r Permissions) bool {
	return (p & r) == r
}

func (p Permissions) String() string {
	return fmt.Sprintf("0b%b", p)
}
