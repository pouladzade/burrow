package payload

import (
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/errors"
)

type TxInput struct {
	Address  crypto.Address
	Amount   uint64
	Sequence uint64
}

func (txIn *TxInput) ValidateBasic() error {
	if txIn.Address == crypto.ZeroAddress {
		return e.Error(e.ErrTxInvalidAddress)
	}
	if txIn.Amount == 0 {
		return e.Error(e.ErrTxInvalidAmount)
	}
	return nil
}
