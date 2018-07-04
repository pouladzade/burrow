package payload

import (
	"fmt"

	"github.com/hyperledger/burrow/util"
)

/*
Payload (Transaction) is an atomic operation on the ledger state.

Account Txs:
 - SendTx         Send coins to address
 - CallTx         Send a msg to a contract that runs in the vm
 - NameTx	  Store some value under a name in the global namereg

Validation Txs:
 - BondTx         New validator posts a bond
 - UnbondTx       Validator leaves

Admin Txs:
 - PermissionsTx
*/

type Type int8

// Types of Payload implementations
const (
	TypeUnknown = Type(0x00)
	// Account transactions
	TypeSend = Type(0x01)
	TypeCall = Type(0x02)
	TypeName = Type(0x03)

	// Validation transactions
	TypeBond   = Type(0x11)
	TypeUnbond = Type(0x12)

	// Admin transactions
	TypePermissions = Type(0x21)
)

var nameFromType = map[Type]string{
	TypeUnknown:     "UnknownTx",
	TypeSend:        "SendTx",
	TypeCall:        "CallTx",
	TypeName:        "NameTx",
	TypeBond:        "BondTx",
	TypeUnbond:      "UnbondTx",
	TypePermissions: "PermissionsTx",
}

var typeFromName = make(map[string]Type)

func init() {
	for t, n := range nameFromType {
		typeFromName[n] = t
	}
}

func TxTypeFromString(name string) Type {
	return typeFromName[name]
}

func (typ Type) String() string {
	name, ok := nameFromType[typ]
	if ok {
		return name
	}
	return "UnknownTx"
}

func (typ Type) MarshalText() ([]byte, error) {
	return []byte(typ.String()), nil
}

func (typ *Type) UnmarshalText(data []byte) error {
	*typ = TxTypeFromString(string(data))
	return nil
}

type Payload interface {
	Inputs() []TxInput
	Outputs() []TxOutput
	Type() Type
}

func InAmount(p Payload) uint64 {
	inAmount := uint64(0)
	for _, input := range p.Inputs() {
		inAmount += input.Amount
	}
	return inAmount
}

func OutAmount(p Payload) uint64 {
	outAmount := uint64(0)
	for _, output := range p.Outputs() {
		outAmount += output.Amount
	}
	return outAmount
}

func Fee(p Payload) uint64 {
	return InAmount(p) - OutAmount(p)
}

func String(p Payload) string {
	return fmt.Sprintf("%s{%s}", p.Type(), util.ToString(p))
}

func New(txType Type) Payload {
	switch txType {
	case TypeSend:
		return &SendTx{}
	case TypeCall:
		return &CallTx{}
	case TypeName:
		return &NameTx{}
	case TypeBond:
		return &BondTx{}
	case TypeUnbond:
		return &UnbondTx{}
	case TypePermissions:
		return &PermissionsTx{}
	}
	return nil
}
