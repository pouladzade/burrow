package test

import (
	"testing"

	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/txs/payload"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeSendTx(t *testing.T, from, to string, amount, fee uint64) *payload.SendTx {
	tx, err := payload.EmptySendTx()
	require.NoError(t, err)

	addSender(t, tx, from, amount, fee)
	addReceiver(t, tx, to, amount)
	return tx
}

func addSender(t *testing.T, tx *payload.SendTx, from string, amount, fee uint64) *payload.SendTx {
	acc := getAccount(t, from)
	tx.AddSender(acc.Address(), acc.Sequence()+1, amount+fee)
	return tx
}

func addReceiver(t *testing.T, tx *payload.SendTx, to string, amount uint64) *payload.SendTx {
	var toAddress crypto.Address
	if to != "" {
		toAddress = accountPool[to].Address()
	} else {
		toAddress = generateNewAddress(t)
	}

	tx.AddReceiver(toAddress, amount)
	return tx
}

func makeNameTx(t *testing.T, from, name, data string, amount, fee uint64) *payload.NameTx {
	acc := getAccount(t, from)
	tx, err := payload.NewNameTx(acc.Address(), acc.Sequence()+1, fee, name, data)
	assert.NoError(t, err)

	return tx
}

func makeCallTx(t *testing.T, from string, address crypto.Address, data []byte, amount, fee uint64) *payload.CallTx {
	acc := getAccount(t, from)
	tx, err := payload.NewCallTx(acc.Address(), address, acc.Sequence()+1, data, 210000, amount, fee)
	assert.NoError(t, err)

	return tx
}
