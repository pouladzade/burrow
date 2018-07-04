package payload

import (
	"fmt"

	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/errors"
)

type TxOutput struct {
	Address crypto.Address
	Amount  uint64
}

func (txOut *TxOutput) ValidateBasic() error {
	if len(txOut.Address) != 20 {
		return e.Error(e.ErrTxInvalidAddress)
	}
	return nil
}

func (txOut *TxOutput) String() string {
	return fmt.Sprintf("TxOutput{%s, Amount:%v}", txOut.Address, txOut.Amount)
}
