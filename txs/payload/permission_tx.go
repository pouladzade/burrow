package payload

import (
	"fmt"

	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/permission"
)

type PermissionsTx struct {
	Modifier    TxInput                `json:"modifier"`
	Modified    crypto.Address         `json:"modified"`
	Permissions permission.Permissions `json:"permissions"`
	Set         bool                   `json:"set"`
}

func NewPermissionsTx(modifier, modified crypto.Address, permission permission.Permissions, set bool, sequence uint64, fee uint64) (*PermissionsTx, error) {
	return &PermissionsTx{
		Modifier: TxInput{
			Address:  modifier,
			Amount:   fee,
			Sequence: sequence,
		},
		Modified:    modified,
		Permissions: permission,
		Set:         set,
	}, nil
}

func (tx *PermissionsTx) Type() Type {
	return TypePermissions
}

func (tx *PermissionsTx) GetInputs() []*TxInput {
	return []*TxInput{&tx.Modifier}
}

func (tx *PermissionsTx) String() string {
	return fmt.Sprintf("PermissionsTx{%v -> %v (%v,%v)}", tx.Modifier, tx.Modified, tx.Permissions, tx.Set)
}
