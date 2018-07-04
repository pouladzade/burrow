package test

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"runtime/debug"
	"testing"
	"time"

	"github.com/hyperledger/burrow/errors"
	"github.com/hyperledger/burrow/execution/events"

	"github.com/hyperledger/burrow/event"
	"github.com/hyperledger/burrow/permission"

	acm "github.com/hyperledger/burrow/account"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/execution"
	"github.com/hyperledger/burrow/txs"
	"github.com/hyperledger/burrow/txs/payload"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _fee uint64 = 10

func setupBatchChecker(m *testing.M) {
	emitter = event.NewEmitter(nopLogger)
	checker = execution.NewBatchChecker(bc1State, bc1.Tip, nopLogger)
	committer = execution.NewBatchCommitter(bc1State, bc1.Tip, emitter, nopLogger)
}

func execTxWaitAccountCall(t *testing.T, tx payload.Payload, name string, address crypto.Address) (*events.EventDataCall, error) {
	env := txs.Enclose(chainID, tx)
	ch := make(chan *events.EventDataCall)
	ctx := context.Background()
	const subscriber = "exexTxWaitEvent"

	require.NoError(t, env.Sign(accountKeys[name]), "Could not sign tx in call: %s", debug.Stack())

	//emitter.Subscribe(ctx, subscriber, event.QueryForEventID(eventid), ch)
	events.SubscribeAccountCall(ctx, emitter, subscriber, address, env.Tx.Hash(), -1, ch)
	defer emitter.UnsubscribeAll(ctx, subscriber)

	err := committer.Execute(env)
	assert.NoError(t, err)

	commit(t)
	ticker := time.NewTicker(2 * time.Second)

	select {
	case eventDataCall := <-ch:
		fmt.Println("MSG: ", eventDataCall)
		return eventDataCall, eventDataCall.Exception.AsError()

	case <-ticker.C:
		return nil, e.Error(e.ErrTimeOut)
	}
}

func commit(t *testing.T) {
	_, err := committer.Commit()

	assert.NoError(t, err)
	// commit and clear caches
	assert.NoError(t, committer.Reset())
	assert.NoError(t, checker.Reset())
}

func signAndExecute(t *testing.T, errorCode int, tx payload.Payload, names ...string) *txs.Envelope {

	signers := make([]acm.AddressableSigner, len(names))
	for i, name := range names {
		signers[i] = accountKeys[name]
	}

	env := txs.Enclose(chainID, tx)
	require.NoError(t, env.Sign(signers...), "Could not sign tx in call: %s", debug.Stack())

	if errorCode != e.ErrNone {
		require.Equal(t, e.Code(checker.Execute(env)), errorCode, "Tx should fail: %s", debug.Stack())
		require.Equal(t, e.Code(checker.Execute(env)), errorCode, "Tx should fail: %s", debug.Stack())
	} else {
		require.NoError(t, checker.Execute(env), "Tx should not fail: %s", debug.Stack())
		require.NoError(t, committer.Execute(env), "Tx should not fail: %s", debug.Stack())
		commit(t)
	}

	return env
}
func getAccount(t *testing.T, name string) *acm.Account {
	account, err := bc1State.GetAccount(accountPool[name].Address())
	require.NoError(t, err)
	require.NotNil(t, account)
	return account
}

func setPermissions(t *testing.T, name string, permissions permission.Permissions) {
	account := getAccount(t, name)
	/// First remove all permissions, then set new one
	account.UnsetPermissions(account.Permissions())
	account.SetPermissions(permissions)
	updateAccount(t, account)

	commit(t)
}

func getBalance(t *testing.T, name string) uint64 {
	return getBalanceByAddress(t, accountPool[name].Address())
}

func getBalanceByAddress(t *testing.T, address crypto.Address) uint64 {
	account, err := bc1State.GetAccount(address)
	require.NoError(t, err)
	require.NotNil(t, account)
	return account.Balance()
}

func checkBalance(t *testing.T, name string, amount uint64) {
	checkBalanceByAddress(t, accountPool[name].Address(), amount)
}

func checkBalanceByAddress(t *testing.T, address crypto.Address, amount uint64) {
	account, err := bc1State.GetAccount(address)
	require.NoError(t, err)
	require.NotNil(t, account)
	assert.Equal(t, account.Balance(), amount)
}

func TestSendTxFails(t *testing.T) {
	setPermissions(t, "alice", permission.Send)
	setPermissions(t, "bob", permission.Call)
	setPermissions(t, "carol", permission.CreateContract)

	tx1 := makeSendTx(t, "alice", "dan", 100, _fee)
	signAndExecute(t, e.ErrNone, tx1, "alice")

	// simple send tx with call perm should fail
	tx2 := makeSendTx(t, "bob", "dan", 100, _fee)
	signAndExecute(t, e.ErrPermDenied, tx2, "bob")

	// simple send tx with create perm should fail
	tx3 := makeSendTx(t, "carol", "dan", 100, _fee)
	signAndExecute(t, e.ErrPermDenied, tx3, "carol")

	// simple send tx to unknown account without create_account perm should fail
	tx5 := makeSendTx(t, "alice", "", 100, _fee)
	signAndExecute(t, e.ErrPermDenied, tx5, "alice")

	// Output amount can  be zero
	tx6 := makeSendTx(t, "alice", "dan", 0, _fee)
	signAndExecute(t, e.ErrNone, tx6, "alice")
}

func TestName(t *testing.T) {
	/*
		setPermissions(t, "alice", permission.Send)
		setPermissions(t, "bob", permission.Name)

		// simple name tx without perm should fail
		tx1 := makeNameTx(t, "alice", "somename", "somedata", 10000, _fee)
		signAndExecute(t, e.ErrNone, tx1, "alice")

		// simple name tx with perm should pass
		tx2 := makeNameTx(t, "bob", "somename", "somedata", 10000, _fee)
		signAndExecute(t, e.ErrPermDenied, tx2, "bob")
	*/
}

func TestCallFails(t *testing.T) {
	setPermissions(t, "alice", 0)
	setPermissions(t, "bob", permission.Send)
	setPermissions(t, "carol", permission.Call)
	setPermissions(t, "dan", permission.CreateContract)

	//-------------------
	// call txs
	_, simpleContractAddr := makeContractAccount(t, []byte{0x60}, 0, 0)

	// simple call tx should fail
	tx1 := makeCallTx(t, "alice", simpleContractAddr, nil, 100, _fee)
	signAndExecute(t, e.ErrPermDenied, tx1, "alice")

	// simple call tx with send permission should fail
	tx2 := makeCallTx(t, "bob", simpleContractAddr, nil, 100, _fee)
	signAndExecute(t, e.ErrPermDenied, tx2, "bob")

	// simple call tx with create permission should fail
	tx3 := makeCallTx(t, "dan", simpleContractAddr, nil, 100, _fee)
	signAndExecute(t, e.ErrPermDenied, tx3, "dan")

	//-------------------
	// create txs

	// simple call create tx should fail
	tx4 := makeCallTx(t, "alice", crypto.Address{}, nil, 100, _fee)
	signAndExecute(t, e.ErrPermDenied, tx4, "alice")

	// simple call create tx with send perm should fail
	tx5 := makeCallTx(t, "bob", crypto.Address{}, nil, 100, _fee)
	signAndExecute(t, e.ErrPermDenied, tx5, "bob")

	// simple call create tx with call perm should fail
	tx6 := makeCallTx(t, "carol", crypto.Address{}, nil, 100, _fee)
	signAndExecute(t, e.ErrPermDenied, tx6, "carol")
}

func TestSendPermission(t *testing.T) {
	setPermissions(t, "alice", permission.Send)
	setPermissions(t, "bob", 0)

	// A single input, having the permission, should succeed
	tx1 := makeSendTx(t, "alice", "carol", 10, _fee)
	signAndExecute(t, e.ErrNone, tx1, "alice")

	tx2 := makeSendTx(t, "alice", "carol", 10, _fee)
	addSender(t, tx2, "bob", 10, _fee)
	addReceiver(t, tx2, "carol", 10)

	// Two inputs, one with permission, one without, should fail
	signAndExecute(t, e.ErrPermDenied, tx2, "alice", "bob")
}

func TestCallPermission(t *testing.T) {
	setPermissions(t, "alice", permission.Call)

	//------------------------------
	// call to greeter contract

	// A single input, having the permission, should succeed
	// 	create simple contract
	_, simpleContractAddr := makeContractAccount(t, []byte{0x60}, 0, 0)

	tx1 := makeCallTx(t, "alice", simpleContractAddr, nil, 100, _fee)
	_, err := execTxWaitAccountCall(t, tx1, "alice", simpleContractAddr)
	fmt.Println(err)
	require.NoError(t, err)

	//----------------------------------------------------------
	// call to contract that calls simple contract - without perm

	// create contract that calls the simple contract
	contractCode1 := callContractCode(simpleContractAddr, 0)
	caller1Acc, caller1Address := makeContractAccount(t, contractCode1, 1000, permission.ZeroPermissions)

	// A single input, having the permission, but the contract doesn't have permission
	// we need to subscribe to the Call event to detect the exception
	tx2 := makeCallTx(t, "alice", caller1Address, nil, 100, _fee)
	_, err = execTxWaitAccountCall(t, tx2, "alice", caller1Address)
	require.Error(t, err)

	//----------------------------------------------------------
	// call to contract that calls simple contract - with perm
	// A single input, having the permission, and the contract has permission
	caller1Acc.SetPermissions(permission.Call)
	updateAccount(t, caller1Acc)
	tx3 := makeCallTx(t, "alice", caller1Address, nil, 100, _fee)
	_, err = execTxWaitAccountCall(t, tx3, "alice", caller1Address)
	require.NoError(t, err)

	//----------------------------------------------------------
	// call to contract that calls contract that calls simple contract - without perm
	// caller1Contract calls simpleContract. caller2Contract calls caller1Contract.
	// caller1Contract does not have call perms, but caller2Contract does.
	contractCode2 := callContractCode(caller1Address, 0)
	caller2Acc, caller2Address := makeContractAccount(t, contractCode2, 1000, 0)

	caller1Acc.UnsetPermissions(permission.Call)
	caller2Acc.SetPermissions(permission.Call)
	updateAccount(t, caller1Acc)
	updateAccount(t, caller2Acc)

	tx4 := makeCallTx(t, "alice", caller2Address, nil, 100, _fee)
	_, err = execTxWaitAccountCall(t, tx4, "alice", caller1Address)
	require.Error(t, err)

	//----------------------------------------------------------
	// call to contract that calls contract that calls simple contract - without perm
	// caller1Contract calls simpleContract. caller2Contract calls caller1Contract.
	// both caller1 and caller2 have permission
	caller1Acc.SetPermissions(permission.Call)
	updateAccount(t, caller1Acc)

	tx5 := makeCallTx(t, "alice", caller2Address, nil, 100, _fee)
	_, err = execTxWaitAccountCall(t, tx5, "alice", caller1Address)
	require.NoError(t, err)
}

func TestCreatePermission(t *testing.T) {
	setPermissions(t, "alice", permission.Call|permission.CreateContract)

	//------------------------------
	// create a simple contract
	contractCode := []byte{0x60}
	createCode := wrapContractForCreateCode(contractCode)

	// A single input, having the permission, should succeed
	tx1 := makeCallTx(t, "alice", crypto.Address{}, createCode, 100, _fee)
	signAndExecute(t, e.ErrNone, tx1, "alice")

	// ensure the contract is there
	contractAddr := crypto.NewContractAddress(tx1.Caller(), tx1.Sequence())
	contractAcc, _ := bc1State.GetAccount(contractAddr)
	require.NotNil(t, contractAcc, "failed to create contract %s", contractAddr)

	if !bytes.Equal(contractAcc.Code(), contractCode) {
		t.Fatalf("contract does not have correct code. Got %X, expected %X", contractAcc.Code(), contractCode)
	}

	//------------------------------
	// create contract that uses the CREATE op
	factoryCode := createContractCode()
	createFactoryCode := wrapContractForCreateCode(factoryCode)

	// A single input, having the permission, should succeed
	tx2 := makeCallTx(t, "alice", crypto.Address{}, createFactoryCode, 100, _fee)
	signAndExecute(t, e.ErrNone, tx2, "alice")

	// ensure the contract is there
	contractAddr = crypto.NewContractAddress(tx2.Caller(), tx2.Sequence())
	contractAcc, _ = bc1State.GetAccount(contractAddr)
	require.NotNil(t, contractAcc, "failed to create contract %s", contractAddr)

	if !bytes.Equal(contractAcc.Code(), factoryCode) {
		t.Fatalf("contract does not have correct code. Got %X, expected %X", contractAcc.Code(), factoryCode)
	}

	//------------------------------
	// call the contract (should FAIL)
	tx3 := makeCallTx(t, "alice", contractAddr, createCode, 100, _fee)
	_, err := execTxWaitAccountCall(t, tx3, "alice", contractAddr)
	require.Error(t, err)

	//------------------------------
	// call the contract (should PASS)
	contractAcc.SetPermissions(permission.CreateContract)
	updateAccount(t, contractAcc)

	tx4 := makeCallTx(t, "alice", contractAddr, createCode, 100, _fee)
	_, err = execTxWaitAccountCall(t, tx4, "alice", contractAddr)
	require.NoError(t, err)

	//--------------------------------
	// call the empty address
	code := callContractCode(crypto.Address{}, 0)

	_, contractAddr2 := makeContractAccount(t, code, 1000, permission.Call|permission.CreateContract)

	// this should call the 0 address but not create ...
	tx5 := makeCallTx(t, "alice", contractAddr2, createCode, 100, _fee)
	_, err = execTxWaitAccountCall(t, tx5, "alice", crypto.Address{})
	require.NoError(t, err)

	zeroAcc, err := bc1State.GetAccount(crypto.Address{})
	require.NoError(t, err)
	require.NotNil(t, zeroAcc)
	if len(zeroAcc.Code()) != 0 {
		t.Fatal("the zero account was given code from a CALL!")
	}
}

func TestCreateAccountPermission(t *testing.T) {
	setPermissions(t, "alice", permission.Send|permission.CreateAccount)
	setPermissions(t, "bob", permission.Send)
	setPermissions(t, "carol", permission.Call)

	aliceBalance := getBalance(t, "alice")
	bobBalance := getBalance(t, "bob")
	carolBalance := getBalance(t, "carol")
	//----------------------------------------------------------
	// SendTx to unknown account

	// A single input, having the permission, should succeed
	tx1 := makeSendTx(t, "alice", "", 5, _fee)
	signAndExecute(t, e.ErrNone, tx1, "alice")

	// Two inputs, both with send, should succeed
	tx2 := makeSendTx(t, "alice", "eve", 5, _fee)
	addSender(t, tx2, "bob", 5, _fee)
	tx2.Outputs()[0].Amount = 10

	signAndExecute(t, e.ErrNone, tx2, "alice", "bob")

	// Two inputs, both with send, one with create, one without, should fail
	tx3 := makeSendTx(t, "alice", "", 5, _fee)
	addSender(t, tx3, "bob", 5, _fee)
	tx3.Outputs()[0].Amount = 10

	signAndExecute(t, e.ErrPermDenied, tx3, "alice", "bob")

	// Two inputs, both with send, one with create, one without, two outputs (one known, one unknown) should fail
	tx4 := makeSendTx(t, "alice", "eve", 5, _fee)
	addSender(t, tx4, "bob", 5, _fee)
	addReceiver(t, tx4, "", 5)

	signAndExecute(t, e.ErrPermDenied, tx4, "alice", "bob")

	// Two inputs, both with send, both with create, should pass
	setPermissions(t, "bob", permission.Send|permission.CreateAccount)
	tx5 := makeSendTx(t, "alice", "", 5, _fee)
	addSender(t, tx5, "bob", 5, _fee)
	tx5.Outputs()[0].Amount = 10

	signAndExecute(t, e.ErrNone, tx5, "alice", "bob")

	// Two inputs, both with send, both with create, two outputs (one known, one unknown) should pass
	tx6 := makeSendTx(t, "alice", "eve", 5, _fee)
	addSender(t, tx6, "bob", 5, _fee)
	addReceiver(t, tx6, "", 5)

	signAndExecute(t, e.ErrNone, tx6, "alice", "bob")

	//----------------------------------------------------------
	// CALL to unknown account

	// call to contract that calls unknown account - without create_account perm
	// create contract that calls the simple contract
	newAddress := generateNewAddress(t)
	contractCode := callContractCode(newAddress, 3)
	_, caller1Addr := makeContractAccount(t, contractCode, 0, 0)

	// A single input, having the call permission, but the contract doesn't have any permission
	tx7 := makeCallTx(t, "carol", caller1Addr, nil, 100, _fee)
	_, err := execTxWaitAccountCall(t, tx7, "carol", caller1Addr)
	require.Equal(t, e.Code(err), e.ErrGeneric)

	// A single input, having the call permission, but the contract doesn't have only call permission
	_, caller2Addr := makeContractAccount(t, contractCode, 0, permission.Call)
	tx8 := makeCallTx(t, "carol", caller2Addr, nil, 100, _fee)
	_, err = execTxWaitAccountCall(t, tx8, "carol", caller2Addr)
	require.Equal(t, e.Code(err), e.ErrGeneric)

	// A single input, having the call permission, but the contract doesn't have call and create account permissions
	_, caller3Addr := makeContractAccount(t, contractCode, 0, permission.Call|permission.CreateAccount)
	tx9 := makeCallTx(t, "carol", caller3Addr, nil, 100, _fee)
	_, err = execTxWaitAccountCall(t, tx9, "carol", caller3Addr)
	require.Equal(t, e.Code(err), e.ErrGeneric)

	// Both input and contract have call and create account permissions
	setPermissions(t, "carol", permission.Call|permission.CreateAccount)
	_, caller4Addr := makeContractAccount(t, contractCode, 0, permission.Call|permission.CreateAccount)
	tx10 := makeCallTx(t, "carol", caller4Addr, nil, 100, _fee)
	_, err = execTxWaitAccountCall(t, tx10, "carol", caller4Addr)
	require.NoError(t, err)

	checkBalance(t, "alice", aliceBalance-(4*(5+_fee)))
	checkBalance(t, "bob", bobBalance-(3*(5+_fee)))
	checkBalance(t, "carol", carolBalance-(100+(4*_fee))) /// 1 successfull transaction + 3 failed transactions
	checkBalanceByAddress(t, newAddress, 3)
	checkBalanceByAddress(t, caller4Addr, 97)
}

// Test creating a contract from futher down the call stack
func TestStackOverflow(t *testing.T) {
	setPermissions(t, "alice", permission.Call|permission.CreateAccount)

	/*
	   contract Factory {
	      address a;
	      function create() returns (address){
	          a = new PreFactory();
	          return a;
	      }
	   }

	   contract PreFactory{
	      address a;
	      function create(Factory c) returns (address) {
	      	a = c.create();
	      	return a;
	      }
	   }
	*/

	// run-time byte code for each of the above
	preFactoryCode, _ := hex.DecodeString("60606040526000357C0100000000000000000000000000000000000000000000000000000000900480639ED933181461003957610037565B005B61004F600480803590602001909190505061007B565B604051808273FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF16815260200191505060405180910390F35B60008173FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF1663EFC81A8C604051817C01000000000000000000000000000000000000000000000000000000000281526004018090506020604051808303816000876161DA5A03F1156100025750505060405180519060200150600060006101000A81548173FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF02191690830217905550600060009054906101000A900473FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF16905061013C565B91905056")
	factoryCode, _ := hex.DecodeString("60606040526000357C010000000000000000000000000000000000000000000000000000000090048063EFC81A8C146037576035565B005B60426004805050606E565B604051808273FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF16815260200191505060405180910390F35B6000604051610153806100E0833901809050604051809103906000F0600060006101000A81548173FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF02191690830217905550600060009054906101000A900473FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF16905060DD565B90566060604052610141806100126000396000F360606040526000357C0100000000000000000000000000000000000000000000000000000000900480639ED933181461003957610037565B005B61004F600480803590602001909190505061007B565B604051808273FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF16815260200191505060405180910390F35B60008173FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF1663EFC81A8C604051817C01000000000000000000000000000000000000000000000000000000000281526004018090506020604051808303816000876161DA5A03F1156100025750505060405180519060200150600060006101000A81548173FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF02191690830217905550600060009054906101000A900473FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF16905061013C565B91905056")
	createData, _ := hex.DecodeString("9ed93318")

	_, preFactoryAddr := makeContractAccount(t, preFactoryCode, 0, permission.Call)
	_, factoryAddr := makeContractAccount(t, factoryCode, 0, permission.Call)

	createData = append(createData, factoryAddr.Word256().Bytes()...)

	// call the pre-factory, triggering the factory to run a create
	tx1 := makeCallTx(t, "alice", preFactoryAddr, createData, 3, _fee)
	_, err := execTxWaitAccountCall(t, tx1, "alice", preFactoryAddr)
	require.Error(t, err)
}

func TestContractSend(t *testing.T) {
	setPermissions(t, "alice", permission.Call)
	/*
	   contract Caller {
	      function send(address x){
	          x.send(msg.value);
	      }
	   }
	*/
	callerCode, _ := hex.DecodeString("60606040526000357c0100000000000000000000000000000000000000000000000000000000900480633e58c58c146037576035565b005b604b6004808035906020019091905050604d565b005b8073ffffffffffffffffffffffffffffffffffffffff16600034604051809050600060405180830381858888f19350505050505b5056")
	sendData, _ := hex.DecodeString("3e58c58c")

	_, caller1Addr := makeContractAccount(t, callerCode, 0, 0)
	_, caller2Addr := makeContractAccount(t, callerCode, 0, permission.Call)

	sendData = append(sendData, accountPool["bob"].Address().Word256().Bytes()...)
	sendAmt := uint64(10)

	aliceBalance := getBalance(t, "alice")
	bobBalance := getBalance(t, "bob")

	tx1 := makeCallTx(t, "alice", caller1Addr, sendData, sendAmt, _fee)
	_, err := execTxWaitAccountCall(t, tx1, "alice", caller1Addr)
	require.Error(t, err)

	tx2 := makeCallTx(t, "alice", caller2Addr, sendData, sendAmt, _fee)
	_, err = execTxWaitAccountCall(t, tx2, "alice", caller2Addr)
	require.NoError(t, err)

	checkBalance(t, "alice", aliceBalance-sendAmt-_fee-_fee)
	checkBalance(t, "bob", bobBalance+sendAmt)
	checkBalanceByAddress(t, caller1Addr, 0)
	checkBalanceByAddress(t, caller2Addr, 0)
}

func TestSelfDestruct(t *testing.T) {
	setPermissions(t, "alice", permission.Send|permission.Call|permission.CreateAccount)

	aliceBalance := getBalance(t, "alice")
	bobBalance := getBalance(t, "bob")
	sendAmt := uint64(1)
	refundedBalance := uint64(100)

	// store 0x1 at 0x1, push an address, then self-destruct:)
	contractCode := []byte{0x60, 0x01, 0x60, 0x01, 0x55, 0x73}
	contractCode = append(contractCode, accountPool["bob"].Address().Bytes()...)
	contractCode = append(contractCode, 0xff)

	_, contractAddr := makeContractAccount(t, contractCode, refundedBalance, 0)

	// send call tx with no data, cause self-destruct
	tx1 := makeCallTx(t, "alice", contractAddr, nil, sendAmt, _fee)
	_, err := execTxWaitAccountCall(t, tx1, "alice", contractAddr)
	require.NoError(t, err)

	// if we do it again, the caller should lose fee
	tx2 := makeCallTx(t, "alice", contractAddr, nil, sendAmt, _fee)
	_, err = execTxWaitAccountCall(t, tx2, "alice", contractAddr)
	require.Equal(t, e.Code(err), e.ErrTimeOut)

	contractAcc, err := bc1State.GetAccount(contractAddr)
	require.NoError(t, err)
	require.Nil(t, contractAcc, "Expected account to be removed")

	checkBalance(t, "alice", aliceBalance-sendAmt-_fee-_fee)
	checkBalance(t, "bob", bobBalance+refundedBalance+sendAmt)
}

func TestTxSequence(t *testing.T) {
	setPermissions(t, "alice", permission.Send)

	sequence1 := getAccount(t, "alice").Sequence()
	sequence2 := getAccount(t, "bob").Sequence()
	for i := 0; i < 100; i++ {
		tx := makeSendTx(t, "alice", "bob", 1, _fee)
		signAndExecute(t, e.ErrNone, tx, "alice")
	}

	require.Equal(t, sequence1+100, getAccount(t, "alice").Sequence())
	require.Equal(t, sequence2, getAccount(t, "bob").Sequence())
}

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% func TestSNativeCALL(t *testing.T) {
// 	stateDB := dbm.NewDB("state", dbBackend, dbDir)
// 	defer stateDB.Close()
// 	genDoc := newBaseGenDoc(permission.ZeroPermissions, permission.ZeroPermissions)
// 	genDoc.Accounts[0].Permissions.Base.Set(permission.Call, true) // give the 0 account permission
// 	genDoc.Accounts[3].Permissions.Base.Set(permission.Bond, true) // some arbitrary permission to play with
// 	genDoc.Accounts[3].Permissions.AddRole("bumble")
// 	genDoc.Accounts[3].Permissions.AddRole("bee")
// 	st, err := MakeGenesisState(stateDB, &genDoc)
// 	require.NoError(t, err)
// 	batchCommitter, emitter := makeExecutor(st)

// 	//----------------------------------------------------------
// 	// Test CALL to SNative contracts

// 	batchCommitter.stateCache.UpdateAccount(doug[0])

// 	fmt.Println("\n#### HasBase")
// 	// HasBase
// 	snativeAddress, pF, data := snativePermTestInputCALL("hasBase", users[3], permission.Bond, false)
// 	testSNativeCALLExpectFail(t, batchCommitter, emitter, doug[0], snativeAddress, data)
// 	testSNativeCALLExpectPass(t, batchCommitter, emitter, doug[0], pF, snativeAddress, data, func(ret []byte) error {
// 		// return value should be true or false as a 32 byte array...
// 		if !IsZeros(ret[:31]) || ret[31] != byte(1) {
// 			return fmt.Errorf("Expected 1. Got %X", ret)
// 		}
// 		return nil
// 	})

// 	fmt.Println("\n#### SetBase")
// 	// SetBase
// 	snativeAddress, pF, data = snativePermTestInputCALL("setBase", users[3], permission.Bond, false)
// 	testSNativeCALLExpectFail(t, batchCommitter, emitter, doug[0], snativeAddress, data)
// 	testSNativeCALLExpectPass(t, batchCommitter, emitter, doug[0], pF, snativeAddress, data, func(ret []byte) error { return nil })
// 	snativeAddress, pF, data = snativePermTestInputCALL("hasBase", users[3], permission.Bond, false)
// 	testSNativeCALLExpectPass(t, batchCommitter, emitter, doug[0], pF, snativeAddress, data, func(ret []byte) error {
// 		// return value should be true or false as a 32 byte array...
// 		if !IsZeros(ret) {
// 			return fmt.Errorf("Expected 0. Got %X", ret)
// 		}
// 		return nil
// 	})
// 	snativeAddress, pF, data = snativePermTestInputCALL("setBase", users[3], permission.CreateContract, true)
// 	testSNativeCALLExpectPass(t, batchCommitter, emitter, doug[0], pF, snativeAddress, data, func(ret []byte) error { return nil })
// 	snativeAddress, pF, data = snativePermTestInputCALL("hasBase", users[3], permission.CreateContract, false)
// 	testSNativeCALLExpectPass(t, batchCommitter, emitter, doug[0], pF, snativeAddress, data, func(ret []byte) error {
// 		// return value should be true or false as a 32 byte array...
// 		if !IsZeros(ret[:31]) || ret[31] != byte(1) {
// 			return fmt.Errorf("Expected 1. Got %X", ret)
// 		}
// 		return nil
// 	})

// 	fmt.Println("\n#### UnsetBase")
// 	// UnsetBase
// 	snativeAddress, pF, data = snativePermTestInputCALL("unsetBase", users[3], permission.CreateContract, false)
// 	testSNativeCALLExpectFail(t, batchCommitter, emitter, doug[0], snativeAddress, data)
// 	testSNativeCALLExpectPass(t, batchCommitter, emitter, doug[0], pF, snativeAddress, data, func(ret []byte) error { return nil })
// 	snativeAddress, pF, data = snativePermTestInputCALL("hasBase", users[3], permission.CreateContract, false)
// 	testSNativeCALLExpectPass(t, batchCommitter, emitter, doug[0], pF, snativeAddress, data, func(ret []byte) error {
// 		if !IsZeros(ret) {
// 			return fmt.Errorf("Expected 0. Got %X", ret)
// 		}
// 		return nil
// 	})

// 	fmt.Println("\n#### SetGlobal")
// 	// SetGlobalPerm
// 	snativeAddress, pF, data = snativePermTestInputCALL("setGlobal", users[3], permission.CreateContract, true)
// 	testSNativeCALLExpectFail(t, batchCommitter, emitter, doug[0], snativeAddress, data)
// 	testSNativeCALLExpectPass(t, batchCommitter, emitter, doug[0], pF, snativeAddress, data, func(ret []byte) error { return nil })
// 	snativeAddress, pF, data = snativePermTestInputCALL("hasBase", users[3], permission.CreateContract, false)
// 	testSNativeCALLExpectPass(t, batchCommitter, emitter, doug[0], pF, snativeAddress, data, func(ret []byte) error {
// 		// return value should be true or false as a 32 byte array...
// 		if !IsZeros(ret[:31]) || ret[31] != byte(1) {
// 			return fmt.Errorf("Expected 1. Got %X", ret)
// 		}
// 		return nil
// 	})

// 	fmt.Println("\n#### HasRole")
// 	// HasRole
// 	snativeAddress, pF, data = snativeRoleTestInputCALL("hasRole", users[3], "bumble")
// 	testSNativeCALLExpectFail(t, batchCommitter, emitter, doug[0], snativeAddress, data)
// 	testSNativeCALLExpectPass(t, batchCommitter, emitter, doug[0], pF, snativeAddress, data, func(ret []byte) error {
// 		if !IsZeros(ret[:31]) || ret[31] != byte(1) {
// 			return fmt.Errorf("Expected 1. Got %X", ret)
// 		}
// 		return nil
// 	})

// 	fmt.Println("\n#### AddRole")
// 	// AddRole
// 	snativeAddress, pF, data = snativeRoleTestInputCALL("hasRole", users[3], "chuck")
// 	testSNativeCALLExpectPass(t, batchCommitter, emitter, doug[0], pF, snativeAddress, data, func(ret []byte) error {
// 		if !IsZeros(ret) {
// 			return fmt.Errorf("Expected 0. Got %X", ret)
// 		}
// 		return nil
// 	})
// 	snativeAddress, pF, data = snativeRoleTestInputCALL("addRole", users[3], "chuck")
// 	testSNativeCALLExpectFail(t, batchCommitter, emitter, doug[0], snativeAddress, data)
// 	testSNativeCALLExpectPass(t, batchCommitter, emitter, doug[0], pF, snativeAddress, data, func(ret []byte) error { return nil })
// 	snativeAddress, pF, data = snativeRoleTestInputCALL("hasRole", users[3], "chuck")
// 	testSNativeCALLExpectPass(t, batchCommitter, emitter, doug[0], pF, snativeAddress, data, func(ret []byte) error {
// 		if !IsZeros(ret[:31]) || ret[31] != byte(1) {
// 			return fmt.Errorf("Expected 1. Got %X", ret)
// 		}
// 		return nil
// 	})

// 	fmt.Println("\n#### RemoveRole")
// 	// RemoveRole
// 	snativeAddress, pF, data = snativeRoleTestInputCALL("removeRole", users[3], "chuck")
// 	testSNativeCALLExpectFail(t, batchCommitter, emitter, doug[0], snativeAddress, data)
// 	testSNativeCALLExpectPass(t, batchCommitter, emitter, doug[0], pF, snativeAddress, data, func(ret []byte) error { return nil })
// 	snativeAddress, pF, data = snativeRoleTestInputCALL("hasRole", users[3], "chuck")
// 	testSNativeCALLExpectPass(t, batchCommitter, emitter, doug[0], pF, snativeAddress, data, func(ret []byte) error {
// 		if !IsZeros(ret) {
// 			return fmt.Errorf("Expected 0. Got %X", ret)
// 		}
// 		return nil
// 	})
// }

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% func TestSNativeTx(t *testing.T) {
// 	stateDB := dbm.NewDB("state", dbBackend, dbDir)
// 	defer stateDB.Close()
// 	genDoc := newBaseGenDoc(permission.ZeroPermissions, permission.ZeroPermissions)
// 	genDoc.Accounts[0].Permissions.Base.Set(permission.Call, true) // give the 0 account permission
// 	genDoc.Accounts[3].Permissions.Base.Set(permission.Bond, true) // some arbitrary permission to play with
// 	genDoc.Accounts[3].Permissions.AddRole("bumble")
// 	genDoc.Accounts[3].Permissions.AddRole("bee")
// 	st, err := MakeGenesisState(stateDB, &genDoc)
// 	require.NoError(t, err)
// 	batchCommitter, _ := makeExecutor(st)

// 	//----------------------------------------------------------
// 	// Test SNativeTx

// 	fmt.Println("\n#### SetBase")
// 	// SetBase
// 	snativeArgs := snativePermTestInputTx("setBase", users[3], permission.Bond, false)
// 	testSNativeTxExpectFail(t, batchCommitter, snativeArgs)
// 	testSNativeTxExpectPass(t, batchCommitter, permission.SetBase, snativeArgs)
// 	acc := getAccount(batchCommitter.stateCache, users[3].Address())
// 	if v, _ := acc.MutablePermissions().Base.Get(permission.Bond); v {
// 		t.Fatal("expected permission to be set false")
// 	}
// 	snativeArgs = snativePermTestInputTx("setBase", users[3], permission.CreateContract, true)
// 	testSNativeTxExpectPass(t, batchCommitter, permission.SetBase, snativeArgs)
// 	acc = getAccount(batchCommitter.stateCache, users[3].Address())
// 	if v, _ := acc.MutablePermissions().Base.Get(permission.CreateContract); !v {
// 		t.Fatal("expected permission to be set true")
// 	}

// 	fmt.Println("\n#### UnsetBase")
// 	// UnsetBase
// 	snativeArgs = snativePermTestInputTx("unsetBase", users[3], permission.CreateContract, false)
// 	testSNativeTxExpectFail(t, batchCommitter, snativeArgs)
// 	testSNativeTxExpectPass(t, batchCommitter, permission.UnsetBase, snativeArgs)
// 	acc = getAccount(batchCommitter.stateCache, users[3].Address())
// 	if v, _ := acc.MutablePermissions().Base.Get(permission.CreateContract); v {
// 		t.Fatal("expected permission to be set false")
// 	}

// 	fmt.Println("\n#### SetGlobal")
// 	// SetGlobalPerm
// 	snativeArgs = snativePermTestInputTx("setGlobal", users[3], permission.CreateContract, true)
// 	testSNativeTxExpectFail(t, batchCommitter, snativeArgs)
// 	testSNativeTxExpectPass(t, batchCommitter, permission.SetGlobal, snativeArgs)
// 	acc = getAccount(batchCommitter.stateCache, acm.GlobalAddress)
// 	if v, _ := acc.MutablePermissions().Base.Get(permission.CreateContract); !v {
// 		t.Fatal("expected permission to be set true")
// 	}

// 	fmt.Println("\n#### AddRole")
// 	// AddRole
// 	snativeArgs = snativeRoleTestInputTx("addRole", users[3], "chuck")
// 	testSNativeTxExpectFail(t, batchCommitter, snativeArgs)
// 	testSNativeTxExpectPass(t, batchCommitter, permission.AddRole, snativeArgs)
// 	acc = getAccount(batchCommitter.stateCache, users[3].Address())
// 	if v := acc.Permissions().HasRole("chuck"); !v {
// 		t.Fatal("expected role to be added")
// 	}

// 	fmt.Println("\n#### RemoveRole")
// 	// RemoveRole
// 	snativeArgs = snativeRoleTestInputTx("removeRole", users[3], "chuck")
// 	testSNativeTxExpectFail(t, batchCommitter, snativeArgs)
// 	testSNativeTxExpectPass(t, batchCommitter, permission.RemoveRole, snativeArgs)
// 	acc = getAccount(batchCommitter.stateCache, users[3].Address())
// 	if v := acc.Permissions().HasRole("chuck"); v {
// 		t.Fatal("expected role to be removed")
// 	}
// }

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% func TestNameTxs(t *testing.T) {
// 	state, err := MakeGenesisState(dbm.NewMemDB(), testGenesisDoc)
// 	require.NoError(t, err)
// 	state.Save()

// 	txs.MinNameRegistrationPeriod = 5
// 	blockchain := newBlockchain(testGenesisDoc, state)
// 	startingBlock := blockchain.LastBlockHeight()

// 	// try some bad names. these should all fail
// 	nameStrings := []string{"", "\n", "123#$%", "\x00", string([]byte{20, 40, 60, 80}),
// 		"baffledbythespectacleinallofthisyouseeehesaidwithouteyessurprised", "no spaces please"}
// 	data := "something about all this just doesn't feel right."
// 	fee := uint64(1000)
// 	numDesiredBlocks := uint64(5)
// 	for _, name := range nameStrings {
// 		amt := fee + numDesiredBlocks*names.NameByteCostMultiplier*names.NameBlockCostMultiplier*
// 			names.NameBaseCost(name, data)
// 		tx, _ := payload.NewNameTx(state, testPrivAccounts[0].PublicKey(), name, data, amt, fee)
// 		txEnv := txs.Enclose(testChainID, tx)
// 		txEnv.Sign(testPrivAccounts[0])

// 		if err := execTxWithState(state, txEnv); err == nil {
// 			t.Fatalf("Expected invalid name error from %s", name)
// 		}
// 	}

// 	// try some bad data. these should all fail
// 	name := "hold_it_chum"
// 	datas := []string{"cold&warm", "!@#$%^&*()", "<<<>>>>", "because why would you ever need a ~ or a & or even a % in a json file? make your case and we'll talk"}
// 	for _, data := range datas {
// 		amt := fee + numDesiredBlocks*names.NameByteCostMultiplier*names.NameBlockCostMultiplier*
// 			names.NameBaseCost(name, data)
// 		tx, _ := payload.NewNameTx(state, testPrivAccounts[0].PublicKey(), name, data, amt, fee)
// 		txEnv := txs.Enclose(testChainID, tx)
// 		txEnv.Sign(testPrivAccounts[0])

// 		if err := execTxWithState(state, txEnv); err == nil {
// 			t.Fatalf("Expected invalid data error from %s", data)
// 		}
// 	}

// 	validateEntry := func(t *testing.T, entry *names.Entry, name, data string, addr crypto.Address, expires uint64) {

// 		if entry == nil {
// 			t.Fatalf("Could not find name %s", name)
// 		}
// 		if entry.Owner != addr {
// 			t.Fatalf("Wrong owner. Got %s expected %s", entry.Owner, addr)
// 		}
// 		if data != entry.Data {
// 			t.Fatalf("Wrong data. Got %s expected %s", entry.Data, data)
// 		}
// 		if name != entry.Name {
// 			t.Fatalf("Wrong name. Got %s expected %s", entry.Name, name)
// 		}
// 		if expires != entry.Expires {
// 			t.Fatalf("Wrong expiry. Got %d, expected %d", entry.Expires, expires)
// 		}
// 	}

// 	// try a good one, check data, owner, expiry
// 	name = "@looking_good/karaoke_bar.broadband"
// 	data = "on this side of neptune there are 1234567890 people: first is OMNIVORE+-3. Or is it. Ok this is pretty restrictive. No exclamations :(. Faces tho :')"
// 	amt := fee + numDesiredBlocks*names.NameByteCostMultiplier*names.NameBlockCostMultiplier*names.NameBaseCost(name, data)
// 	tx, _ := payload.NewNameTx(state, testPrivAccounts[0].PublicKey(), name, data, amt, fee)
// 	txEnv := txs.Enclose(testChainID, tx)
// 	require.NoError(t, txEnv.Sign(testPrivAccounts[0]))
// 	if err := execTxWithState(state, txEnv); err != nil {
// 		t.Fatal(err)
// 	}
// 	entry, err := state.GetNameEntry(name)
// 	require.NoError(t, err)
// 	validateEntry(t, entry, name, data, testPrivAccounts[0].Address(), startingBlock+numDesiredBlocks)

// 	// fail to update it as non-owner, in same block
// 	tx, _ = payload.NewNameTx(state, testPrivAccounts[1].PublicKey(), name, data, amt, fee)
// 	txEnv = txs.Enclose(testChainID, tx)
// 	require.NoError(t, txEnv.Sign(testPrivAccounts[1]))
// 	if err := execTxWithState(state, txEnv); err == nil {
// 		t.Fatal("Expected error")
// 	}

// 	// update it as owner, just to increase expiry, in same block
// 	// NOTE: we have to resend the data or it will clear it (is this what we want?)
// 	tx, _ = payload.NewNameTx(state, testPrivAccounts[0].PublicKey(), name, data, amt, fee)
// 	txEnv = txs.Enclose(testChainID, tx)
// 	require.NoError(t, txEnv.Sign(testPrivAccounts[0]))
// 	if err := execTxWithStateNewBlock(state, blockchain, txEnv); err != nil {
// 		t.Fatal(err)
// 	}
// 	entry, err = state.GetNameEntry(name)
// 	require.NoError(t, err)
// 	validateEntry(t, entry, name, data, testPrivAccounts[0].Address(), startingBlock+numDesiredBlocks*2)

// 	// update it as owner, just to increase expiry, in next block
// 	tx, _ = payload.NewNameTx(state, testPrivAccounts[0].PublicKey(), name, data, amt, fee)
// 	txEnv = txs.Enclose(testChainID, tx)
// 	require.NoError(t, txEnv.Sign(testPrivAccounts[0]))
// 	if err := execTxWithStateNewBlock(state, blockchain, txEnv); err != nil {
// 		t.Fatal(err)
// 	}
// 	entry, err = state.GetNameEntry(name)
// 	require.NoError(t, err)
// 	validateEntry(t, entry, name, data, testPrivAccounts[0].Address(), startingBlock+numDesiredBlocks*3)

// 	// fail to update it as non-owner
// 	// Fast forward
// 	for blockchain.Tip.LastBlockHeight() < entry.Expires-1 {
// 		commitNewBlock(state, blockchain)
// 	}
// 	tx, _ = payload.NewNameTx(state, testPrivAccounts[1].PublicKey(), name, data, amt, fee)
// 	txEnv = txs.Enclose(testChainID, tx)
// 	require.NoError(t, txEnv.Sign(testPrivAccounts[1]))
// 	if err := execTxWithStateAndBlockchain(state, blockchain.Tip, txEnv); err == nil {
// 		t.Fatal("Expected error")
// 	}
// 	commitNewBlock(state, blockchain)

// 	// once expires, non-owner succeeds
// 	tx, _ = payload.NewNameTx(state, testPrivAccounts[1].PublicKey(), name, data, amt, fee)
// 	txEnv = txs.Enclose(testChainID, tx)
// 	require.NoError(t, txEnv.Sign(testPrivAccounts[1]))
// 	if err := execTxWithStateAndBlockchain(state, blockchain.Tip, txEnv); err != nil {
// 		t.Fatal(err)
// 	}
// 	entry, err = state.GetNameEntry(name)
// 	require.NoError(t, err)
// 	validateEntry(t, entry, name, data, testPrivAccounts[1].Address(), blockchain.LastBlockHeight()+numDesiredBlocks)

// 	// update it as new owner, with new data (longer), but keep the expiry!
// 	data = "In the beginning there was no thing, not even the beginning. It hadn't been here, no there, nor for that matter anywhere, not especially because it had not to even exist, let alone to not. Nothing especially odd about that."
// 	oldCredit := amt - fee
// 	numDesiredBlocks = 10
// 	amt = fee + numDesiredBlocks*names.NameByteCostMultiplier*names.NameBlockCostMultiplier*names.NameBaseCost(name, data) - oldCredit
// 	tx, _ = payload.NewNameTx(state, testPrivAccounts[1].PublicKey(), name, data, amt, fee)
// 	txEnv = txs.Enclose(testChainID, tx)
// 	require.NoError(t, txEnv.Sign(testPrivAccounts[1]))
// 	if err := execTxWithStateAndBlockchain(state, blockchain.Tip, txEnv); err != nil {
// 		t.Fatal(err)
// 	}
// 	entry, err = state.GetNameEntry(name)
// 	require.NoError(t, err)
// 	validateEntry(t, entry, name, data, testPrivAccounts[1].Address(), blockchain.LastBlockHeight()+numDesiredBlocks)

// 	// test removal
// 	amt = fee
// 	data = ""
// 	tx, _ = payload.NewNameTx(state, testPrivAccounts[1].PublicKey(), name, data, amt, fee)
// 	txEnv = txs.Enclose(testChainID, tx)
// 	require.NoError(t, txEnv.Sign(testPrivAccounts[1]))
// 	if err := execTxWithStateNewBlock(state, blockchain, txEnv); err != nil {
// 		t.Fatal(err)
// 	}
// 	entry, err = state.GetNameEntry(name)
// 	require.NoError(t, err)
// 	if entry != nil {
// 		t.Fatal("Expected removed entry to be nil")
// 	}

// 	// create entry by key0,
// 	// test removal by key1 after expiry
// 	name = "looking_good/karaoke_bar"
// 	data = "some data"
// 	amt = fee + numDesiredBlocks*names.NameByteCostMultiplier*names.NameBlockCostMultiplier*names.NameBaseCost(name, data)
// 	tx, _ = payload.NewNameTx(state, testPrivAccounts[0].PublicKey(), name, data, amt, fee)
// 	txEnv = txs.Enclose(testChainID, tx)
// 	require.NoError(t, txEnv.Sign(testPrivAccounts[0]))
// 	if err := execTxWithStateAndBlockchain(state, blockchain.Tip, txEnv); err != nil {
// 		t.Fatal(err)
// 	}
// 	entry, err = state.GetNameEntry(name)
// 	require.NoError(t, err)
// 	validateEntry(t, entry, name, data, testPrivAccounts[0].Address(), blockchain.LastBlockHeight()+numDesiredBlocks)
// 	// Fast forward
// 	for blockchain.Tip.LastBlockHeight() < entry.Expires {
// 		commitNewBlock(state, blockchain)
// 	}

// 	amt = fee
// 	data = ""
// 	tx, _ = payload.NewNameTx(state, testPrivAccounts[1].PublicKey(), name, data, amt, fee)
// 	txEnv = txs.Enclose(testChainID, tx)
// 	require.NoError(t, txEnv.Sign(testPrivAccounts[1]))
// 	if err := execTxWithStateNewBlock(state, blockchain, txEnv); err != nil {
// 		t.Fatal(err)
// 	}
// 	entry, err = state.GetNameEntry(name)
// 	require.NoError(t, err)
// 	if entry != nil {
// 		t.Fatal("Expected removed entry to be nil")
// 	}
// }

// // TODO: test overflows.
// // TODO: test for unbonding validators.
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% func TestTxs(t *testing.T) {
// 	state, privAccounts := makeGenesisState(3, true, 1000, 1, true, 1000)

// 	//val0 := state.GetValidatorInfo(privValidators[0].Address())
// 	acc0 := getAccount(state, privAccounts[0].Address())
// 	acc1 := getAccount(state, privAccounts[1].Address())

// 	// SendTx.
// 	{
// 		stateSendTx := state.Copy(dbm.NewMemDB())
// 		tx := &payload.SendTx{
// 			Inputs: []*payload.TxInput{
// 				{
// 					Address:  acc0.Address(),
// 					Amount:   1,
// 					Sequence: acc0.Sequence() + 1,
// 				},
// 			},
// 			Outputs: []*payload.TxOutput{
// 				{
// 					Address: acc1.Address(),
// 					Amount:  1,
// 				},
// 			},
// 		}

// 		txEnv := txs.Enclose(testChainID, tx)
// 		require.NoError(t, txEnv.Sign(privAccounts[0]))
// 		err := execTxWithState(stateSendTx, txEnv)
// 		if err != nil {
// 			t.Errorf("Got error in executing send transaction, %v", err)
// 		}
// 		newAcc0 := getAccount(stateSendTx, acc0.Address())
// 		if acc0.Balance()-1 != newAcc0.Balance() {
// 			t.Errorf("Unexpected newAcc0 balance. Expected %v, got %v",
// 				acc0.Balance()-1, newAcc0.Balance())
// 		}
// 		newAcc1 := getAccount(stateSendTx, acc1.Address())
// 		if acc1.Balance()+1 != newAcc1.Balance() {
// 			t.Errorf("Unexpected newAcc1 balance. Expected %v, got %v",
// 				acc1.Balance()+1, newAcc1.Balance())
// 		}
// 	}

// 	// CallTx. Just runs through it and checks the transfer. See vm, rpc tests for more
// 	{
// 		stateCallTx := state.Copy(dbm.NewMemDB())
// 		balance := doug[0].Balance()
// 		stateCallTx.UpdateAccount(doug[0])
// 		tx := &txs.CallTx{
// 			Input: &txs.TxInput{
// 				Address:   acc0.Address(),
// 				Amount:    1,
// 				Sequence:  acc0.Sequence() + 1,
// 				PublicKey: acc0PubKey,
// 			},
// 			Address:  addressPtr(doug[0]),
// 			GasLimit: 10,
// 		}

// 		txEnv := txs.Enclose(testChainID, tx)
// 		require.NoError(t, txEnv.Sign(privAccounts[0]))
// 		err := execTxWithState(stateCallTx, txEnv)
// 		if err != nil {
// 			t.Errorf("Got error in executing call transaction, %v", err)
// 		}
// 		newAcc0 := getAccount(stateCallTx, acc0.Address())
// 		if acc0.Balance()-1 != newAcc0.Balance() {
// 			t.Errorf("Unexpected newAcc0 balance. Expected %v, got %v",
// 				acc0.Balance()-1, newAcc0.Balance())
// 		}
// 		doug0 := getAccount(stateCallTx, doug[0].Address())
// 		if balance+1 != doug0.Balance() {
// 			t.Errorf("Unexpected newAcc1 balance. Expected %v, got %v",
// 				balance+1, doug0.Balance())
// 		}
// 	}
// 	trygetacc0 := getAccount(state, privAccounts[0].Address())
// 	fmt.Println(trygetacc0.Address())

// 	// NameTx.
// 	{
// 		entryName := "satoshi"
// 		entryData := `
// A  purely   peer-to-peer   version   of   electronic   cash   would   allow   online
// payments  to  be  sent   directly  from  one  party  to  another  without   going  through  a
// financial institution.   Digital signatures provide part of the solution, but the main
// benefits are lost if a trusted third party is still required to prevent double-spending.
// We propose a solution to the double-spending problem using a peer-to-peer network.
// The   network   timestamps   transactions  by  hashing   them   into   an   ongoing   chain   of
// hash-based proof-of-work, forming a record that cannot be changed without redoing
// the proof-of-work.   The longest chain not only serves as proof of the sequence of
// events witnessed, but proof that it came from the largest pool of CPU power.   As
// long as a majority of CPU power is controlled by nodes that are not cooperating to
// attack the network, they'll generate the longest chain and outpace attackers.   The
// network itself requires minimal structure.   Messages are broadcast on a best effort
// basis,   and   nodes   can   leave  and   rejoin   the  network   at  will,  accepting   the   longest
// proof-of-work chain as proof of what happened while they were gone `
// 		entryAmount := uint64(10000)

// 		stateNameTx := state
// 		tx := &payload.NameTx{
// 			Input: &payload.TxInput{
// 				Address:  acc0.Address(),
// 				Amount:   entryAmount,
// 				Sequence: acc0.Sequence() + 1,
// 			},
// 			Name: entryName,
// 			Data: entryData,
// 		}

// 		txEnv := txs.Enclose(testChainID, tx)
// 		require.NoError(t, txEnv.Sign(privAccounts[0]))

// 		err := execTxWithState(stateNameTx, txEnv)
// 		if err != nil {
// 			t.Errorf("Got error in executing call transaction, %v", err)
// 		}
// 		newAcc0 := getAccount(stateNameTx, acc0.Address())
// 		if acc0.Balance()-entryAmount != newAcc0.Balance() {
// 			t.Errorf("Unexpected newAcc0 balance. Expected %v, got %v",
// 				acc0.Balance()-entryAmount, newAcc0.Balance())
// 		}
// 		entry, err := stateNameTx.GetNameEntry(entryName)
// 		require.NoError(t, err)
// 		if entry == nil {
// 			t.Errorf("Expected an entry but got nil")
// 		}
// 		if entry.Data != entryData {
// 			t.Errorf("Wrong data stored")
// 		}

// 		// test a bad string
// 		tx.Data = string([]byte{0, 1, 2, 3, 127, 128, 129, 200, 251})
// 		tx.Input.Sequence += 1
// 		txEnv = txs.Enclose(testChainID, tx)
// 		require.NoError(t, txEnv.Sign(privAccounts[0]))
// 		err = execTxWithState(stateNameTx, txEnv)
// 		if _, ok := err.(payload.ErrTxInvalidString); !ok {
// 			t.Errorf("Expected invalid string error. Got: %s", err.Error())
// 		}
// 	}

// 	// BondTx. TODO
// 	/*
// 		{
// 			state := state.Copy()
// 			tx := &payload.BondTx{
// 				PublicKey: acc0PubKey.(acm.PublicKeyEd25519),
// 				Inputs: []*payload.TxInput{
// 					&payload.TxInput{
// 						Address:  acc0.Address(),
// 						Amount:   1,
// 						Sequence: acc0.Sequence() + 1,
// 						PublicKey:   acc0PubKey,
// 					},
// 				},
// 				UnbondTo: []*payload.TxOutput{
// 					&payload.TxOutput{
// 						Address: acc0.Address(),
// 						Amount:  1,
// 					},
// 				},
// 			}
// 			tx.Signature = privAccounts[0] acm.ChainSign(testChainID, tx).(crypto.SignatureEd25519)
// 			tx.Inputs[0].Signature = privAccounts[0] acm.ChainSign(testChainID, tx)
// 			err := execTxWithState(state, tx)
// 			if err != nil {
// 				t.Errorf("Got error in executing bond transaction, %v", err)
// 			}
// 			newAcc0 := getAccount(state, acc0.Address())
// 			if newAcc0.Balance() != acc0.Balance()-1 {
// 				t.Errorf("Unexpected newAcc0 balance. Expected %v, got %v",
// 					acc0.Balance()-1, newAcc0.Balance())
// 			}
// 			_, acc0Val := state.BondedValidators.GetByAddress(acc0.Address())
// 			if acc0Val == nil {
// 				t.Errorf("acc0Val not present")
// 			}
// 			if acc0Val.BondHeight != blockchain.LastBlockHeight()+1 {
// 				t.Errorf("Unexpected bond height. Expected %v, got %v",
// 					blockchain.LastBlockHeight(), acc0Val.BondHeight)
// 			}
// 			if acc0Val.VotingPower != 1 {
// 				t.Errorf("Unexpected voting power. Expected %v, got %v",
// 					acc0Val.VotingPower, acc0.Balance())
// 			}
// 			if acc0Val.Accum != 0 {
// 				t.Errorf("Unexpected accum. Expected 0, got %v",
// 					acc0Val.Accum)
// 			}
// 		} */

// 	// TODO UnbondTx.

// }

// // give a contract perms for an snative, call it, it calls the snative, but shouldn't have permission
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% func testSNativeCALLExpectFail(t *testing.T, batchCommitter *executor, emitter event.Emitter, doug *acm.Account,
// 	snativeAddress crypto.Address, data []byte) {
// 	testSNativeCALL(t, false, batchCommitter, emitter, doug, 0, snativeAddress, data, nil)
// }

// // give a contract perms for an snative, call it, it calls the snative, ensure the check funciton (f) succeeds
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% func testSNativeCALLExpectPass(t *testing.T, batchCommitter *executor, emitter event.Emitter, doug *acm.Account, snativePerm permission.PermFlag,
// 	snativeAddress crypto.Address, data []byte, f func([]byte) error) {
// 	testSNativeCALL(t, true, batchCommitter, emitter, doug, snativePerm, snativeAddress, data, f)
// }

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% func testSNativeCALL(t *testing.T, expectPass bool, batchCommitter *executor, emitter event.Emitter, doug *acm.Account,
// 	snativePerm permission.PermFlag, snativeAddress crypto.Address, data []byte, f func([]byte) error) {
// 	if expectPass {
// 		doug.MutablePermissions().Base.Set(snativePerm, true)
// 	}

// 	doug.SetCode(callContractCode(snativeAddress))
// 	dougAddress := doug.Address()

// 	batchCommitter.stateCache.UpdateAccount(doug)
// 	tx, _ := payload.NewCallTx(batchCommitter.stateCache, users[0].PublicKey(), &dougAddress, data, 100, 10000, 100)
// 	txEnv := txs.Enclose(testChainID, tx)
// 	require.NoError(t, txEnv.Sign(users[0]))
// 	t.Logf("subscribing to %v", evm_events.EventStringAccountCall(snativeAddress))
// 	ev, err := execTxWaitAccountCall(t, batchCommitter, emitter, txEnv, snativeAddress)
// 	if err == ExceptionTimeOut {
// 		t.Fatal("Timed out waiting for event")
// 	}
// 	if expectPass {
// 		require.NoError(t, err)
// 		ret := ev.Return
// 		if err := f(ret); err != nil {
// 			t.Fatal(err)
// 		}
// 	} else {
// 		require.Error(t, err)
// 	}
// }

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% func testSNativeTxExpectFail(t *testing.T, batchCommitter *executor, snativeArgs snatives.PermArgs) {
// 	testSNativeTx(t, false, batchCommitter, 0, snativeArgs)
// }

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% func testSNativeTxExpectPass(t *testing.T, batchCommitter *executor, perm permission.PermFlag,
// 	snativeArgs snatives.PermArgs) {
// 	testSNativeTx(t, true, batchCommitter, perm, snativeArgs)
// }

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% func testSNativeTx(t *testing.T, expectPass bool, batchCommitter *executor, perm permission.PermFlag,
// 	snativeArgs snatives.PermArgs) {
// 	if expectPass {
// 		acc := getAccount(batchCommitter.stateCache, users[0].Address())
// 		acc.MutablePermissions().Base.Set(perm, true)
// 		batchCommitter.stateCache.UpdateAccount(acc)
// 	}
// 	tx, _ := payload.NewPermissionsTx(batchCommitter.stateCache, users[0].PublicKey(), snativeArgs)
// 	txEnv := txs.Enclose(testChainID, tx)
// 	require.NoError(t, txEnv.Sign(users[0]))
// 	err := batchCommitter.Execute(txEnv)
// 	if expectPass {
// 		if err != nil {
// 			t.Fatal("Unexpected exception", err)
// 		}
// 	} else {
// 		if err == nil {
// 			t.Fatal("Expected exception")
// 		}
// 	}
// }

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% func boolToWord256(v bool) Word256 {
// 	var vint byte
// 	if v {
// 		vint = 0x1
// 	} else {
// 		vint = 0x0
// 	}
// 	return LeftPadWord256([]byte{vint})
// }

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% func permNameToFuncID(name string) []byte {
// 	function, err := permissionsContract.FunctionByName(name)
// 	if err != nil {
// 		panic("didn't find snative function signature!")
// 	}
// 	id := function.ID()
// 	return id[:]
// }

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% func snativePermTestInputCALL(name string, user acm.AddressableSigner, perm permission.PermFlag,
// 	val bool) (addr crypto.Address, pF permission.PermFlag, data []byte) {
// 	addr = permissionsContract.Address()
// 	switch name {
// 	case "hasBase", "unsetBase":
// 		data = user.Address().Word256().Bytes()
// 		data = append(data, Uint64ToWord256(uint64(perm)).Bytes()...)
// 	case "setBase":
// 		data = user.Address().Word256().Bytes()
// 		data = append(data, Uint64ToWord256(uint64(perm)).Bytes()...)
// 		data = append(data, boolToWord256(val).Bytes()...)
// 	case "setGlobal":
// 		data = Uint64ToWord256(uint64(perm)).Bytes()
// 		data = append(data, boolToWord256(val).Bytes()...)
// 	}
// 	data = append(permNameToFuncID(name), data...)
// 	var err error
// 	if pF, err = permission.PermStringToFlag(name); err != nil {
// 		panic(fmt.Sprintf("failed to convert perm string (%s) to flag", name))
// 	}
// 	return
// }

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% func snativePermTestInputTx(name string, user acm.AddressableSigner, perm permission.PermFlag,
// 	val bool) (snativeArgs snatives.PermArgs) {

// 	switch name {
// 	case "hasBase":
// 		snativeArgs = snatives.HasBaseArgs(user.Address(), perm)
// 	case "unsetBase":
// 		snativeArgs = snatives.UnsetBaseArgs(user.Address(), perm)
// 	case "setBase":
// 		snativeArgs = snatives.SetBaseArgs(user.Address(), perm, val)
// 	case "setGlobal":
// 		snativeArgs = snatives.SetGlobalArgs(perm, val)
// 	}
// 	return
// }

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% func snativeRoleTestInputCALL(name string, user acm.AddressableSigner,
// 	role string) (addr crypto.Address, pF permission.PermFlag, data []byte) {
// 	addr = permissionsContract.Address()
// 	data = user.Address().Word256().Bytes()
// 	data = append(data, RightPadBytes([]byte(role), 32)...)
// 	data = append(permNameToFuncID(name), data...)

// 	var err error
// 	if pF, err = permission.PermStringToFlag(name); err != nil {
// 		panic(fmt.Sprintf("failed to convert perm string (%s) to flag", name))
// 	}
// 	return
// }

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% func snativeRoleTestInputTx(name string, user acm.AddressableSigner, role string) (snativeArgs snatives.PermArgs) {
// 	switch name {
// 	case "hasRole":
// 		snativeArgs = snatives.HasRoleArgs(user.Address(), role)
// 	case "addRole":
// 		snativeArgs = snatives.AddRoleArgs(user.Address(), role)
// 	case "removeRole":
// 		snativeArgs = snatives.RemoveRoleArgs(user.Address(), role)
// 	}
// 	return
// }
