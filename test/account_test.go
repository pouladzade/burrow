package test

import (
	"math/rand"
	"testing"

	acm "github.com/hyperledger/burrow/account"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/execution/evm"
	"github.com/hyperledger/burrow/permission"
)

func setupAccountPool(m *testing.M) {
	names := []string{"alice", "bob", "carol", "dan", "eve", "satoshi", "vbuterin", "finterran", "b00f", "pouladzade", "benjaminbollen", "silasdavis", "ebuchman", "zramsay", "seanyoung", "VoR0220",
		"smblucker", "shuangjj", "compleatang", "prestonjbyrne", "ietv", "bryant1410", "jaekwon", "ratranqu", "dennismckinnon"}

	accountPool = make(map[string]*acm.Account)
	accountKeys = make(map[string]acm.PrivateAccount)

	for i, name := range names {
		balance := rand.New(rand.NewSource(int64(i))).Uint64()
		privateAccount := acm.GeneratePrivateAccountFromSecret(name)
		account := acm.NewAccount(privateAccount.PrivateKey().GetPublicKey(), permission.DefaultAccountPermissions)

		account.AddToBalance(balance)

		accountPool[name] = account
		accountKeys[name] = privateAccount
	}
}

func makeAccount(t *testing.T, balance uint64, permissions permission.Permissions) (*acm.Account, crypto.Address) {
	account := acm.NewAccount(generateNewPublicKey(t), permissions)
	account.AddToBalance(balance)
	updateAccount(t, account)
	commit(t)

	return account, account.Address()
}

func makeContractAccount(t *testing.T, code []byte, balance uint64, permissions permission.Permissions) (*acm.Account, crypto.Address) {
	deriveFrom := getAccount(t, "b00f")
	contractAcc := evm.DeriveNewAccount(deriveFrom, permissions, nopLogger)
	contractAcc.SetCode(code)
	contractAcc.AddToBalance(balance)
	updateAccount(t, contractAcc)
	updateAccount(t, deriveFrom)
	commit(t)

	return contractAcc, contractAcc.Address()
}
