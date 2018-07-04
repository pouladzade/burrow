package txs

import (
	"testing"

	acm "github.com/hyperledger/burrow/account"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/txs/payload"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignature(t *testing.T) {
	privKey1 := crypto.PrivateKeyFromSecret("secret1", crypto.CurveTypeEd25519)
	privKey2 := crypto.PrivateKeyFromSecret("secret2", crypto.CurveTypeEd25519)
	privKey3 := crypto.PrivateKeyFromSecret("secret3", crypto.CurveTypeEd25519)

	pubKey1 := privKey1.GetPublicKey()
	pubKey2 := privKey2.GetPublicKey()
	pubKey3 := privKey3.GetPublicKey()

	tx, _ := payload.EmptySendTx()
	tx.AddReceiver(crypto.Address{1}, 1)
	tx.AddSender(pubKey1.Address(), 1, 1)
	tx.AddSender(pubKey2.Address(), 1, 1)
	tx.AddSender(pubKey3.Address(), 1, 1)

	txEnv := Enclose(chainID, tx)

	privAcc1 := acm.ConcretePrivateAccount{PrivateKey: privKey1}.PrivateAccount()
	privAcc2 := acm.ConcretePrivateAccount{PrivateKey: privKey2}.PrivateAccount()
	err := txEnv.Sign(privAcc1, privAcc2)
	assert.Error(t, err)

	err = txEnv.Verify()
	require.Error(t, err)

	privAcc3 := acm.ConcretePrivateAccount{PrivateKey: privKey3}.PrivateAccount()
	err = txEnv.Sign(privAcc1, privAcc2, privAcc3)
	require.NoError(t, err)

	err = txEnv.Verify()
	require.NoError(t, err)

	/// TODO: Add more tests here
}
