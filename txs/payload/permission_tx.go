package payload

import (
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/permission"
)

type PermissionsTx struct {
	data permissionsData
}
type permissionsData struct {
	Modifier    TxInput                `json:"modifier"`
	Modified    TxOutput               `json:"modified"`
	Permissions permission.Permissions `json:"permissions"`
	Set         bool                   `json:"set"`
}

func NewPermissionsTx(modifier, modified crypto.Address, permission permission.Permissions, set bool, sequence, fee uint64) (*PermissionsTx, error) {
	return &PermissionsTx{
		data: permissionsData{
			Modifier: TxInput{
				Address:  modifier,
				Sequence: sequence,
				Amount:   fee,
			},
			Modified: TxOutput{
				Address: modified,
				Amount:  0,
			},

			Permissions: permission,
			Set:         set,
		},
	}, nil
}

func (tx *PermissionsTx) Type() Type                          { return TypePermissions }
func (tx *PermissionsTx) Modifier() crypto.Address            { return tx.data.Modifier.Address }
func (tx *PermissionsTx) Modified() crypto.Address            { return tx.data.Modified.Address }
func (tx *PermissionsTx) Fee() uint64                         { return tx.data.Modifier.Amount }
func (tx *PermissionsTx) Permissions() permission.Permissions { return tx.data.Permissions }
func (tx *PermissionsTx) Set() bool                           { return tx.data.Set }

func (tx *PermissionsTx) Inputs() []TxInput {
	return []TxInput{tx.data.Modifier}
}

func (tx *PermissionsTx) Outputs() []TxOutput {
	return []TxOutput{tx.data.Modified}
}
