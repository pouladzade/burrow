package payload

import (
	"regexp"

	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/errors"
	"github.com/hyperledger/burrow/execution/names"
)

// Name should be file system lik
// Data should be anything permitted in JSON
var regexpAlphaNum = regexp.MustCompile("^[a-zA-Z0-9._/-@]*$")
var regexpJSON = regexp.MustCompile(`^[a-zA-Z0-9_/ \-+"':,\n\t.{}()\[\]]*$`)

type NameTx struct {
	data nameData
}

type nameData struct {
	Account TxInput `json:"account"`
	Name    string  `json:"name"`
	Data    string  `json:"data"`
}

func NewNameTx(address crypto.Address, sequence, fee uint64, name, data string) (*NameTx, error) {
	return &NameTx{
		data: nameData{
			Account: TxInput{
				Address:  address,
				Sequence: sequence,
				Amount:   fee,
			},
			Name: name,
			Data: data,
		},
	}, nil
}

func (tx *NameTx) Type() Type              { return TypeName }
func (tx *NameTx) Address() crypto.Address { return tx.data.Account.Address }
func (tx *NameTx) Fee() uint64             { return tx.data.Account.Amount }
func (tx *NameTx) Name() string            { return tx.data.Name }
func (tx *NameTx) Data() string            { return tx.data.Data }

func (tx *NameTx) Inputs() []TxInput {
	return []TxInput{tx.data.Account}
}

func (tx *NameTx) Outputs() []TxOutput {
	return []TxOutput{}
}

func (tx *NameTx) ValidateStrings() error {
	if len(tx.data.Name) == 0 {
		return e.Error(e.ErrTxInvalidString)
	}
	if len(tx.data.Name) > names.MaxNameLength {
		return e.Errorf(e.ErrTxInvalidString, "Name is too long. Max %d bytes", names.MaxNameLength)
	}
	if len(tx.data.Data) > names.MaxDataLength {
		return e.Errorf(e.ErrTxInvalidString, "Data is too long. Max %d bytes", names.MaxDataLength)
	}

	if !validateNameRegEntryName(tx.data.Name) {
		return e.Errorf(e.ErrTxInvalidString, "Invalid characters found in NameTx.Name (%s). Only alphanumeric, underscores, dashes, forward slashes, and @ are allowed", tx.Name)
	}

	if !validateNameRegEntryData(tx.data.Data) {
		return e.Errorf(e.ErrTxInvalidString, "Invalid characters found in NameTx.Data (%s). Only the kind of things found in a JSON file are allowed", tx.Data)
	}

	return nil
}

// filter strings
func validateNameRegEntryName(name string) bool {
	return regexpAlphaNum.Match([]byte(name))
}

func validateNameRegEntryData(data string) bool {
	return regexpJSON.Match([]byte(data))
}
