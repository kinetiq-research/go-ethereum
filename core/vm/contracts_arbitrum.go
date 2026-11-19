// Copyright 2024 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package vm

import (
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto/poseidon"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

var (
	PrecompiledContractsBeforeArbOS30       = make(map[common.Address]PrecompiledContract)
	PrecompiledAddressesBeforeArbOS30       []common.Address
	PrecompiledContractsStartingFromArbOS30 = make(map[common.Address]PrecompiledContract)
	PrecompiledAddressesStartingFromArbOS30 []common.Address
	PrecompiledContractsStartingFromArbOS41 = make(map[common.Address]PrecompiledContract)
	PrecompiledAddressesStartingFromArbOS41 []common.Address
	PrecompiledContractsStartingFromArbOS50 = make(map[common.Address]PrecompiledContract)
	PrecompiledAddressesStartingFromArbOS50 []common.Address
	PrecompiledContractsStartingFromArbOS60 = make(map[common.Address]PrecompiledContract)
	PrecompiledAddressesStartingFromArbOS60 []common.Address
	PrecompiledContractsStartingFromArbOS62 = make(map[common.Address]PrecompiledContract)
	PrecompiledAddressesStartingFromArbOS62 []common.Address
)

// PoseidonPrecompileAddress is the address of the Poseidon native precompile.
var PoseidonPrecompileAddress = common.BytesToAddress([]byte{0x01, 0x02})

// PrecompiledContractsPoseidon contains the Poseidon native precompile, active from ArbOS 62.
var PrecompiledContractsPoseidon = PrecompiledContracts{
	PoseidonPrecompileAddress: &poseidonHash{},
}

// PoseidonProfileBN254T3 selects BN254 Poseidon with x^5 S-box, width 3,
// 8 full and 57 partial rounds (circomlibjs / iden3 go-iden3-crypto v2.0.0).
const PoseidonProfileBN254T3 = 0x01

const poseidonInputLength = 1 + 2*32

var (
	errPoseidonInputLength    = errors.New("invalid poseidon input length")
	errPoseidonUnknownProfile = errors.New("unknown poseidon profile")
	errPoseidonNonCanonical   = errors.New("poseidon input is not a canonical field element")
)

// poseidonHash implements the Poseidon native precompile.
//
// Input (65 bytes): profile ID (1 byte) || x (32 bytes) || y (32 bytes), with x
// and y big-endian and lower than the BN254 scalar field modulus.
// Output (32 bytes): Poseidon(x, y), big-endian.
type poseidonHash struct{}

func (c *poseidonHash) RequiredGas(input []byte) uint64 {
	return params.PoseidonHashGas
}

func (c *poseidonHash) Run(input []byte) ([]byte, error) {
	if len(input) != poseidonInputLength {
		return nil, errPoseidonInputLength
	}
	if input[0] != PoseidonProfileBN254T3 {
		return nil, errPoseidonUnknownProfile
	}
	var x, y uint256.Int
	x.SetBytes32(input[1:33])
	y.SetBytes32(input[33:65])
	if !poseidon.IsCanonical(&x) || !poseidon.IsCanonical(&y) {
		return nil, errPoseidonNonCanonical
	}
	hash := poseidon.Hash2(&x, &y)
	out := hash.Bytes32()
	return out[:], nil
}

func (c *poseidonHash) Name() string {
	return "POSEIDON"
}
