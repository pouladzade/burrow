package payload

import (
	"github.com/hyperledger/burrow/crypto"
)

type SendTx struct {
	data sendData
}
type sendData struct {
	Senders   []TxInput  `json:"sender"`
	Receivers []TxOutput `json:"receiver"`
}

func EmptySendTx() (*SendTx, error) {
	return &SendTx{}, nil
}

func NewSendTx(from, to crypto.Address, sequence, amount, fee uint64) (*SendTx, error) {
	tx := &SendTx{}
	tx.AddSender(from, sequence, amount+fee)
	tx.AddReceiver(to, amount)

	return tx, nil
}

func (tx *SendTx) Type() Type          { return TypeSend }
func (tx *SendTx) Inputs() []TxInput   { return tx.data.Senders }
func (tx *SendTx) Outputs() []TxOutput { return tx.data.Receivers }

func (tx *SendTx) AddSender(address crypto.Address, sequence, amount uint64) {
	tx.data.Senders = append(tx.data.Senders, TxInput{
		Address:  address,
		Amount:   amount,
		Sequence: sequence,
	})
}

func (tx *SendTx) AddReceiver(address crypto.Address, amount uint64) {
	tx.data.Receivers = append(tx.data.Receivers, TxOutput{
		Address: address,
		Amount:  amount,
	})
}
