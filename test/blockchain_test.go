package test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	acm "github.com/hyperledger/burrow/account"
	"github.com/hyperledger/burrow/blockchain"
	"github.com/hyperledger/burrow/execution"
	"github.com/stretchr/testify/assert"
	dbm "github.com/tendermint/tmlibs/db"
)

func setupBlockchain(m *testing.M) {
	bc1Db = dbm.NewMemDB()
	bc1State, _ = execution.MakeGenesisState(bc1Db, genesisDoc)
	bc1, _ = blockchain.LoadOrNewBlockchain(bc1Db, genesisDoc, nopLogger)
}

func updateAccount(t *testing.T, account *acm.Account) {
	_, err := bc1State.Update(func(ws execution.Updatable) error {
		return ws.UpdateAccount(account)
	})
	require.NoError(t, err)
}

func TestPersistedState(t *testing.T) {

	bc1.CommitBlock(time.Now(), []byte{0x1, 0x2}, []byte{0x2, 0x3})
	bc1.CommitBlock(time.Now(), []byte{0x1, 0x2}, []byte{0x2, 0x3})
	/// load blockchain
	bc2, err := blockchain.LoadOrNewBlockchain(bc1Db, genesisDoc, nopLogger)

	assert.NoError(t, err)
	//assert.Equal(t, bc1.LastBlockHash(), bc2.LastBlockHash())
	assert.Equal(t, bc1.LastBlockHeight()-1, bc2.LastBlockHeight())
	//assert.Equal(t, bc1.LastBlockTime(), bc2.LastBlockTime())
	assert.Equal(t, bc1.AppHashAfterLastBlock(), bc2.AppHashAfterLastBlock())
}
