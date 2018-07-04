package payload

import (
	"github.com/hyperledger/burrow/crypto"
)

type UnbondTx struct {
	data unbondData
}

type unbondData struct {
	From TxInput  `json:"from"` // Validator
	To   TxOutput `json:"to"`
}

func NewUnbondTx(from, to crypto.Address, amount, sequence, fee uint64) Payload {
	return &UnbondTx{
		data: unbondData{
			From: TxInput{
				Address:  from,
				Sequence: sequence,
				Amount:   amount + fee,
			},
			To: TxOutput{
				Address: to,
				Amount:  amount,
			},
		},
	}
}

func (tx *UnbondTx) Type() Type           { return TypeUnbond }
func (tx *UnbondTx) From() crypto.Address { return tx.data.From.Address }
func (tx *UnbondTx) To() crypto.Address   { return tx.data.To.Address }
func (tx *UnbondTx) Amount() uint64       { return tx.data.To.Amount }
func (tx *UnbondTx) Fee() uint64          { return tx.data.From.Amount - tx.data.To.Amount }

func (tx *UnbondTx) Inputs() []TxInput {
	return []TxInput{tx.data.From}
}

func (tx *UnbondTx) Outputs() []TxOutput {
	return []TxOutput{tx.data.To}
}
