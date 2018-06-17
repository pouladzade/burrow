package test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/hyperledger/burrow/crypto"
)

func generateNewAddress(t *testing.T) crypto.Address {
	return generateNewPublicKey(t).Address()
}

func generateNewPublicKey(t *testing.T) crypto.PublicKey {
	privateKey, err := crypto.GeneratePrivateKey(nil, crypto.CurveTypeEd25519)
	assert.NoError(t, err)
	return privateKey.GetPublicKey()
}
