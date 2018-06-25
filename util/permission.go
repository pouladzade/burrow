// Copyright 2017 Monax Industries Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package util

import (
	acm "github.com/hyperledger/burrow/account"
	"github.com/hyperledger/burrow/account/state"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/permission"
)

// Get permissions on an account or fall back to global value
// CONTRACT: it is the duty of the contract writer to call known permissions
// we do not convey if a permissions is not set
// (unlike in state/execution, where we guarantee HasPermissions is called
// on known permissions and panics else)
// If the perm is not defined in the acc nor set by default in GlobalPermissions,
// this function returns false.
// Get permissions on an account or fall back to global value
func HasPermissions(getter state.AccountGetter, account *acm.Account, permissions permission.Permissions) bool {
	if err := permissions.EnsureValid(); err != nil {
		return false
	}

	globalAccount, err := getter.GetAccount(acm.GlobalPermissionsAddress)
	if err != nil {
		return false
	}

	if globalAccount.HasPermissions(permissions) {
		return true
	}

	if account.HasPermissions(permissions) {
		return true
	}

	return false
}

func HaveSendPermission(accountGetter state.AccountGetter, accs map[crypto.Address]*acm.Account) bool {
	for _, acc := range accs {
		if !HasSendPermission(accountGetter, acc) {
			return false
		}
	}
	return true
}

func HaveCreateAccountPermission(accountGetter state.AccountGetter, accs map[crypto.Address]*acm.Account) bool {
	for _, acc := range accs {
		if !HasCreateAccountPermission(accountGetter, acc) {
			return false
		}
	}
	return true
}

func HasSendPermission(accountGetter state.AccountGetter, acc *acm.Account) bool {
	return HasPermissions(accountGetter, acc, permission.Send)
}

func HasNamePermission(accountGetter state.AccountGetter, acc *acm.Account) bool {
	return HasPermissions(accountGetter, acc, permission.Name)
}

func HasCallPermission(accountGetter state.AccountGetter, acc *acm.Account) bool {
	return HasPermissions(accountGetter, acc, permission.Call)
}

func HasCreateContractPermission(accountGetter state.AccountGetter, acc *acm.Account) bool {
	return HasPermissions(accountGetter, acc, permission.CreateContract)
}

func HasCreateAccountPermission(accountGetter state.AccountGetter, acc *acm.Account) bool {
	return HasPermissions(accountGetter, acc, permission.CreateAccount)
}

func HasBondPermission(accountGetter state.AccountGetter, acc *acm.Account) bool {
	return HasPermissions(accountGetter, acc, permission.Bond)
}

func HasModifyPermission(accountGetter state.AccountGetter, acc *acm.Account) bool {
	return HasPermissions(accountGetter, acc, permission.ModifyPermission)
}
