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

package evm

import (
	"testing"

	acm "github.com/hyperledger/burrow/account"
	. "github.com/hyperledger/burrow/binary"
	"github.com/hyperledger/burrow/crypto"
	. "github.com/hyperledger/burrow/execution/evm/asm"
	. "github.com/hyperledger/burrow/execution/evm/asm/bc"
	"github.com/hyperledger/burrow/permission"
	"github.com/stretchr/testify/assert"
)

// These code segment helpers exercise the MSTORE MLOAD MSTORE cycle to test
// both of the memory operations. Each MSTORE is done on the memory boundary
// (at MSIZE) which Solidity uses to find guaranteed unallocated memory.

// storeAtEnd expects the value to be stored to be on top of the stack, it then
// stores that value at the current memory boundary
func storeAtEnd() []byte {
	// Pull in MSIZE (to carry forward to MLOAD), swap in value to store, store it at MSIZE
	return MustSplice(MSIZE, SWAP1, DUP2, MSTORE)
}

func returnAfterStore() []byte {
	return MustSplice(PUSH1, 32, DUP2, RETURN)
}

// Store the top element of the stack (which is a 32-byte word) in memory
// and return it. Useful for a simple return value.
func return1() []byte {
	return MustSplice(PUSH1, 0, MSTORE, returnWord())
}

func returnWord() []byte {
	// PUSH1 => return size, PUSH1 => return offset, RETURN
	return MustSplice(PUSH1, 32, PUSH1, 0, RETURN)
}

func pushInt64(i int64) []byte {
	return pushWord(Int64ToWord256(i))
}

// Produce bytecode for a PUSH<N>, b_1, ..., b_N where the N is number of bytes
// contained in the unpadded word
func pushWord(word Word256) []byte {
	leadingZeros := byte(0)
	for leadingZeros < 32 {
		if word[leadingZeros] == 0 {
			leadingZeros++
		} else {
			return MustSplice(byte(PUSH32)-leadingZeros, word[leadingZeros:])
		}
	}
	return MustSplice(PUSH1, 0)
}

func TestPushWord(t *testing.T) {
	word := Int64ToWord256(int64(2133213213))
	assert.Equal(t, MustSplice(PUSH4, 0x7F, 0x26, 0x40, 0x1D), pushWord(word))
	word[0] = 1
	assert.Equal(t, MustSplice(PUSH32,
		1, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0x7F, 0x26, 0x40, 0x1D), pushWord(word))
	assert.Equal(t, MustSplice(PUSH1, 0), pushWord(Word256{}))
	assert.Equal(t, MustSplice(PUSH1, 1), pushWord(Int64ToWord256(1)))
}

// Kind of indirect test of Splice, but here to avoid import cycles
func TestBytecode(t *testing.T) {
	assert.Equal(t,
		MustSplice(1, 2, 3, 4, 5, 6),
		MustSplice(1, 2, 3, MustSplice(4, 5, 6)))
	assert.Equal(t,
		MustSplice(1, 2, 3, 4, 5, 6, 7, 8),
		MustSplice(1, 2, 3, MustSplice(4, MustSplice(5), 6), 7, 8))
	assert.Equal(t,
		MustSplice(PUSH1, 2),
		MustSplice(byte(PUSH1), 0x02))
	assert.Equal(t,
		[]byte{},
		MustSplice(MustSplice(MustSplice())))

	contractAccount := acm.NewContractAccount(crypto.AddressFromWord256(Int64ToWord256(102)), permission.ZeroAccountPermissions)
	addr := contractAccount.Address()
	gas1, gas2 := byte(0x1), byte(0x1)
	value := byte(0x69)
	inOff, inSize := byte(0x0), byte(0x0) // no call data
	retOff, retSize := byte(0x0), byte(0x20)
	contractCodeBytecode := MustSplice(PUSH1, retSize, PUSH1, retOff, PUSH1, inSize, PUSH1,
		inOff, PUSH1, value, PUSH20, addr, PUSH2, gas1, gas2, CALL, PUSH1, retSize,
		PUSH1, retOff, RETURN)
	contractCode := []byte{0x60, retSize, 0x60, retOff, 0x60, inSize, 0x60, inOff, 0x60, value, 0x73}
	contractCode = append(contractCode, addr[:]...)
	contractCode = append(contractCode, []byte{0x61, gas1, gas2, 0xf1, 0x60, 0x20, 0x60, 0x0, 0xf3}...)
	assert.Equal(t, contractCode, contractCodeBytecode)
}

func TestConcat(t *testing.T) {
	assert.Equal(t,
		[]byte{0x01, 0x02, 0x03, 0x04},
		Concat([]byte{0x01, 0x02}, []byte{0x03, 0x04}))
}

func TestSubslice(t *testing.T) {
	const size = 10
	data := make([]byte, size)
	for i := 0; i < size; i++ {
		data[i] = byte(i)
	}
	for n := int64(0); n < size; n++ {
		data = data[:n]
		for offset := int64(-size); offset < size; offset++ {
			for length := int64(-size); length < size; length++ {
				_, ok := subslice(data, offset, length)
				if offset < 0 || length < 0 || n < offset {
					assert.False(t, ok)
				} else {
					assert.True(t, ok)
				}
			}
		}
	}
}
