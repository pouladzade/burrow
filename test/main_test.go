package test

import (
	"os"
	"testing"

	"github.com/hyperledger/burrow/account/state"
	"github.com/hyperledger/burrow/event"
	"github.com/hyperledger/burrow/execution/evm"

	acm "github.com/hyperledger/burrow/account"
	"github.com/hyperledger/burrow/blockchain"
	"github.com/hyperledger/burrow/execution"
	"github.com/hyperledger/burrow/genesis"
	"github.com/hyperledger/burrow/logging"
	dbm "github.com/tendermint/tmlibs/db"
)

var accountPool map[string]*acm.Account
var accountKeys map[string]acm.PrivateAccount /// private keys
var genesisDoc *genesis.GenesisDoc
var chainID string
var bc1 *blockchain.Blockchain
var bc1Db dbm.DB
var bc1State *execution.State
var emitter event.Emitter
var checker execution.BatchExecutor
var committer execution.BatchCommitter
var nopLogger *logging.Logger
var evm1Cache *state.Cache
var evm1 *evm.VM

func TestMain(m *testing.M) {

	setupLogger(m)
	setupAccountPool(m)
	setupGenesisDoc(m)
	setupBlockchain(m)
	setupBatchChecker(m)
	setupEVM(m)

	exitCode := m.Run()

	os.Exit(exitCode)
}
