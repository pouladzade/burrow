package spec

import (
	"fmt"

	acm "github.com/hyperledger/burrow/account"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/keys"
	"github.com/hyperledger/burrow/permission"
	ptypes "github.com/hyperledger/burrow/permission/types"
)

type TemplateAccount struct {
	// Template accounts sharing a name will be merged when merging genesis specs
	Name string `json:",omitempty" toml:",omitempty"`
	// Address  is convenient to have in file for reference, but otherwise ignored since derived from PublicKey
	Address     *crypto.Address   `json:",omitempty" toml:",omitempty"`
	NodeAddress *crypto.Address   `json:",omitempty" toml:",omitempty"`
	PublicKey   *crypto.PublicKey `json:",omitempty" toml:",omitempty"`
	Amount      *uint64           `json:",omitempty" toml:",omitempty"`
	Power       *uint64           `json:",omitempty" toml:",omitempty"`
	Permissions []string          `json:",omitempty" toml:",omitempty"`
	Roles       []string          `json:",omitempty" toml:",omitempty"`
}

func (ta TemplateAccount) Validator(keyClient keys.KeyClient, generateNodeKeys bool) (acm.Validator, error) {
	var err error
	publicKey, _, err := ta.RealisePubKeyAndAddress(keyClient)
	if err != nil {
		return nil, err
	}

	amountBonded := DefaultPower
	if ta.Power != nil {
		amountBonded = *ta.Power
	}

	account := acm.NewAccount(publicKey, permission.ZeroAccountPermissions)
	account.AddToBalance(amountBonded)

	validator := acm.AsValidator(account)

	return validator, nil
}

func (ta TemplateAccount) AccountPermissions() (ptypes.AccountPermissions, error) {
	basePerms, err := permission.BasePermissionsFromStringList(ta.Permissions)
	if err != nil {
		return permission.ZeroAccountPermissions, nil
	}
	return ptypes.AccountPermissions{
		Base:  basePerms,
		Roles: ta.Roles,
	}, nil
}

func (ta TemplateAccount) Account(keyClient keys.KeyClient) (*acm.Account, error) {

	publicKey, _, err := ta.RealisePubKeyAndAddress(keyClient)
	if err != nil {
		return nil, err
	}

	amount := DefaultAmount
	if ta.Amount != nil {
		amount = *ta.Amount
	}

	permissions := permission.DefaultAccountPermissions.Clone()
	if ta.Permissions != nil {
		permissions, err = ta.AccountPermissions()
		if err != nil {
			return nil, err
		}
	}

	account := acm.NewAccount(publicKey, permissions)
	account.AddToBalance(amount)
	return account, nil
}

// Adds a public key and address to the template. If PublicKey will try to fetch it by Address.
// If both PublicKey and Address are not set will use the keyClient to generate a new keypair
func (ta TemplateAccount) RealisePubKeyAndAddress(keyClient keys.KeyClient) (pubKey crypto.PublicKey, address crypto.Address, err error) {
	if ta.PublicKey == nil {
		if ta.Address == nil {
			// If neither PublicKey or Address set then generate a new one
			address, err = keyClient.Generate(ta.Name, crypto.CurveTypeEd25519)
			if err != nil {
				return
			}
		} else {
			address = *ta.Address
		}
		// Get the (possibly existing) key
		pubKey, err = keyClient.PublicKey(address)
		if err != nil {
			return
		}
	} else {
		address = (*ta.PublicKey).Address()
		if ta.Address != nil && *ta.Address != address {
			err = fmt.Errorf("template address %s does not match public key derived address %s", ta.Address,
				ta.PublicKey)
		}
		pubKey = *ta.PublicKey
	}
	return
}
