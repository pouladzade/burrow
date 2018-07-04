package payload

import (
	"github.com/hyperledger/burrow/crypto"
)

type BondTx struct {
	data bondData
}

type bondData struct {
	From      TxInput          `json:"from"`
	To        TxOutput         `json:"to"`         // Validator
	PublicKey crypto.PublicKey `json:"public_key"` // Validator
}

func NewBondTx(from crypto.Address, to crypto.PublicKey, amount, sequence, fee uint64) (*BondTx, error) {
	return &BondTx{
		data: bondData{
			From: TxInput{
				Address:  from,
				Sequence: sequence,
				Amount:   amount + fee,
			},
			To: TxOutput{
				Address: to.Address(),
				Amount:  amount,
			},
			PublicKey: to,
		},
	}, nil
}

func (tx *BondTx) Type() Type                  { return TypeBond }
func (tx *BondTx) From() crypto.Address        { return tx.data.From.Address }
func (tx *BondTx) To() crypto.Address          { return tx.data.To.Address }
func (tx *BondTx) PublicKey() crypto.PublicKey { return tx.data.PublicKey }
func (tx *BondTx) Amount() uint64              { return tx.data.To.Amount }
func (tx *BondTx) Fee() uint64                 { return tx.data.From.Amount - tx.data.To.Amount }

func (tx *BondTx) Inputs() []TxInput {
	return []TxInput{tx.data.From}
}

func (tx *BondTx) Outputs() []TxOutput {
	return []TxOutput{tx.data.To}
}
