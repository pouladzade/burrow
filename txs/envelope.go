package txs

import (
	"fmt"

	"github.com/hyperledger/burrow/errors"

	acm "github.com/hyperledger/burrow/account"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/txs/payload"
)

type Codec interface {
	Encoder
	Decoder
}

type Encoder interface {
	EncodeTx(envelope *Envelope) ([]byte, error)
}

type Decoder interface {
	DecodeTx(txBytes []byte) (*Envelope, error)
}

// An envelope contains both the signable Tx and the signatures for each input (in signatories)
type Envelope struct {
	Signatories []Signatory
	Tx          Tx
}

// Enclose a Payload in an Envelope so it is ready to be signed by first wrapping the Payload
// as a Tx (including ChainID) and writing it to the Tx field of the Envelope
func Enclose(chainID string, payload payload.Payload) *Envelope {
	body := NewTx(payload)
	body.ChainID = chainID
	return body.Enclose()
}

func (txEnv *Envelope) String() string {
	return fmt.Sprintf("TxEnvelope{Signatures: %v, Tx: %s}", len(txEnv.Signatories), txEnv.Tx)
}

// Signatory contains signature and PublicKey to identify the signer
type Signatory struct {
	PublicKey crypto.PublicKey
	Signature crypto.Signature
}

// Verifies the validity of the Signatories' Signatures in the Envelope. The Signatories must
// appear in the same order as the inputs as returned by Tx.GetInputs().
func (txEnv *Envelope) Verify() error {
	if len(txEnv.Signatories) == 0 {
		return e.Errorf(e.ErrTxInvalidSignature, "transaction envelope contains no (successfully unmarshalled) signatories")
	}

	errPrefix := fmt.Sprintf("could not verify transaction %X", txEnv.Tx.Hash())
	inputs := txEnv.Tx.Payload.Inputs()
	if len(inputs) != len(txEnv.Signatories) {
		return e.Errorf(e.ErrTxInvalidSignature, "%s: number of inputs (= %v) should equal number of signatories (= %v)",
			errPrefix, len(inputs), len(txEnv.Signatories))
	}
	signBytes, err := txEnv.Tx.SignBytes()
	if err != nil {
		return e.Errorf(e.ErrTxInvalidSignature, "%s: could not generate SignBytes: %v", errPrefix, err)
	}
	// Expect order to match (we could build lookup but we want Verify to be quicker than Sign which does order sigs)
	for i, s := range txEnv.Signatories {
		if inputs[i].Address != s.PublicKey.Address() {
			return e.Errorf(e.ErrTxInvalidSignature, "signatory %v has address %v but input %v has address %v",
				i, s.PublicKey.Address(), i, inputs[i].Address)
		}
		if !s.PublicKey.Verify(signBytes, s.Signature) {
			return e.Errorf(e.ErrTxInvalidSignature, "invalid signature in signatory %v ", s.PublicKey.Address())
		}
	}

	return nil
}

// Sign the Tx Envelope by adding Signatories containing the signatures for each TxInput.
// signing accounts for each input must be provided (in any order).
func (txEnv *Envelope) Sign(signingAccounts ...acm.AddressableSigner) error {

	// Clear any existing
	txEnv.Signatories = nil
	signBytes, err := txEnv.Tx.SignBytes()
	if err != nil {
		return err
	}
	signingAccountMap := make(map[crypto.Address]acm.AddressableSigner)
	for _, sa := range signingAccounts {
		signingAccountMap[sa.Address()] = sa
	}
	// Sign in order of inputs
	for i, in := range txEnv.Tx.Payload.Inputs() {
		sa, ok := signingAccountMap[in.Address]
		if !ok {
			return e.Errorf(e.ErrTxInvalidSignature, "account to sign %v (position %v) not passed to Sign, passed: %v", in, i, signingAccounts)
		}
		signature, err := sa.Sign(signBytes)
		if err != nil {
			return err
		}
		publicKey := sa.PublicKey()
		txEnv.Signatories = append(txEnv.Signatories, Signatory{
			PublicKey: publicKey,
			Signature: signature,
		})
	}
	return nil
}
