package execution

import (
	"fmt"
	"sync"

	acm "github.com/hyperledger/burrow/account"
	"github.com/hyperledger/burrow/account/state"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/keys"
	burrow_sync "github.com/hyperledger/burrow/sync"
)

// Accounts pairs an underlying state.Reader with a KeyClient to provide a signing variant of an account
// it also maintains a lock over addresses to provide a linearisation of signing events using SequentialSigningAccount
type Accounts struct {
	burrow_sync.RingMutex
	state.Reader
	keyClient keys.KeyClient
}

type SigningAccount struct {
	*acm.Account
	crypto.Signer
}

type SequentialSigningAccount struct {
	accountLocker sync.Locker
	getter        func() (*SigningAccount, error)
}

func NewAccounts(reader state.Reader, keyClient keys.KeyClient, mutexCount int) *Accounts {
	return &Accounts{
		// TODO: use the no hash variant of RingMutex after it has a test
		RingMutex: *burrow_sync.NewRingMutexXXHash(mutexCount),
		Reader:    reader,
		keyClient: keyClient,
	}
}
func (accs *Accounts) SigningAccount(address crypto.Address, signer crypto.Signer) (*SigningAccount, error) {
	account, err := state.GetAccount(accs, address)
	if err != nil {
		return nil, err
	}
	// If the account is unknown to us return a zeroed account
	if account == nil {
		pubKey, err := accs.keyClient.PublicKey(address)
		if err != nil {
			return nil, err
		}
		account = acm.NewAccount(pubKey.Address())
	}

	return &SigningAccount{
		Account: account,
		Signer:  signer,
	}, nil
}

func (accs *Accounts) SequentialSigningAccount(address crypto.Address) (*SequentialSigningAccount, error) {
	signer, err := keys.AddressableSigner(accs.keyClient, address)
	if err != nil {
		return nil, err
	}
	return &SequentialSigningAccount{
		accountLocker: accs.Mutex(address.Bytes()),
		getter: func() (*SigningAccount, error) {
			return accs.SigningAccount(address, signer)
		},
	}, nil
}

func (accs *Accounts) SequentialSigningAccountFromPrivateKey(privateKeyBytes []byte) (*SequentialSigningAccount, error) {
	if len(privateKeyBytes) != 64 {
		return nil, fmt.Errorf("private key is not of the right length: %d\n", len(privateKeyBytes))
	}
	privateAccount, err := acm.GeneratePrivateAccountFromPrivateKeyBytes(privateKeyBytes)
	if err != nil {
		return nil, err
	}
	return &SequentialSigningAccount{
		accountLocker: accs.Mutex(privateAccount.Address().Bytes()),
		getter: func() (*SigningAccount, error) {
			return accs.SigningAccount(privateAccount.Address(), privateAccount)
		},
	}, nil
}

// Gets signing account from onr of private key or address - failing if both are provided
func (accs *Accounts) GetSequentialSigningAccount(address, privateKey []byte) (*SequentialSigningAccount, error) {
	if len(address) > 0 {
		if len(privateKey) > 0 {
			return nil, fmt.Errorf("address and private key provided but only one or the other should be given")
		}
		address, err := crypto.AddressFromBytes(address)
		if err != nil {
			return nil, err
		}
		return accs.SequentialSigningAccount(address)
	}

	return accs.SequentialSigningAccountFromPrivateKey(privateKey)
}

type UnlockFunc func()

func (ssa *SequentialSigningAccount) Lock() (*SigningAccount, UnlockFunc, error) {
	ssa.accountLocker.Lock()
	account, err := ssa.getter()
	if err != nil {
		ssa.accountLocker.Unlock()
		return nil, nil, err
	}
	return account, ssa.accountLocker.Unlock, err
}

func (sa *SigningAccount) PublicKey() crypto.PublicKey {
	return crypto.PublicKey{}
}
