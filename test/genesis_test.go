package test

import (
	"math/rand"
	"testing"
	"time"

	acm "github.com/hyperledger/burrow/account"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/genesis"
	"github.com/hyperledger/burrow/permission"
	"github.com/stretchr/testify/assert"
)

func setupGenesisDoc(m *testing.M) {
	numValidators := 80
	names := make(map[crypto.Address]string, len(accountPool))
	accounts := make([]*acm.Account, len(accountPool))
	validators := make([]acm.Validator, numValidators)
	i := 0

	for name, account := range accountPool {
		accounts[i] = account
		names[account.Address()] = name
		i++
	}

	for i := 0; i < numValidators; i++ {
		balance := rand.New(rand.NewSource(int64(i))).Uint64()
		privateKey, _ := crypto.GeneratePrivateKey(nil, crypto.CurveTypeEd25519)
		publicKey := privateKey.GetPublicKey()
		account := acm.NewAccount(publicKey.Address())

		account.AddToBalance(balance)

		validator := acm.AsValidator(account, publicKey)

		validators[i] = validator
	}
	genesisDoc = genesis.MakeGenesisDoc("test-chain", nil, time.Now(), permission.ZeroPermissions, names, accounts, validators)
	chainID = genesisDoc.ChainID()
}

func TestGenesisDocFromJSON(t *testing.T) {
	// Check we have matching serialisation after a round trip
	bs, err := genesisDoc.JSONBytes()
	assert.NoError(t, err)

	genDocOut, err := genesis.GenesisDocFromJSON(bs)
	assert.NoError(t, err)

	bsOut, err := genDocOut.JSONBytes()
	assert.NoError(t, err)

	assert.Equal(t, bs, bsOut)
	assert.Equal(t, genesisDoc.Hash(), genDocOut.Hash())
}
