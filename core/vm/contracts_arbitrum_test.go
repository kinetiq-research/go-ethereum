// Copyright 2026 The go-ethereum Authors
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
	"bytes"
	"math/big"
	"slices"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

// Registered here, not in the allPrecompiles literal, so that contracts_test.go
// stays identical to upstream.
func init() {
	allPrecompiles[PoseidonPrecompileAddress] = &poseidonHash{}
}

func TestPrecompiledPoseidon(t *testing.T)      { testJson("poseidon", "0102", t) }
func TestPrecompiledPoseidonFail(t *testing.T)  { testJsonFail("poseidon", "0102", t) }
func BenchmarkPrecompiledPoseidon(b *testing.B) { benchJson("poseidon", "0102", b) }

func TestPrecompiledPoseidonOOG(t *testing.T) {
	tests, err := loadJson("poseidon")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		testPrecompiledOOG("0102", test, t)
	}
}

// TestPoseidonActivation calls the precompile through the EVM and checks that
// it is active from ArbOS 62 on Arbitrum chains and nowhere else.
func TestPoseidonActivation(t *testing.T) {
	// Nitro's gethhook fills the per-ArbOS-version precompile sets. Do the same
	// for ArbOS 62; the older sets stay empty.
	PrecompiledContractsStartingFromArbOS62[PoseidonPrecompileAddress] = PrecompiledContractsPoseidon[PoseidonPrecompileAddress]
	PrecompiledAddressesStartingFromArbOS62 = []common.Address{PoseidonPrecompileAddress}
	t.Cleanup(func() {
		delete(PrecompiledContractsStartingFromArbOS62, PoseidonPrecompileAddress)
		PrecompiledAddressesStartingFromArbOS62 = nil
	})

	const gas = 100_000
	var (
		caller = common.HexToAddress("0xcccccccccccccccccccccccccccccccccccccccc")
		one    = common.BigToHash(big.NewInt(1)).Bytes()
		two    = common.BigToHash(big.NewInt(2)).Bytes()
		input  = slices.Concat([]byte{PoseidonProfileBN254T3}, one, two)
		want   = common.FromHex("115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a")
		// Unknown profile: the precompile runs and fails.
		badInput = slices.Concat([]byte{0x02}, one, two)
	)
	for _, tc := range []struct {
		name     string
		arbitrum bool
		arbos    uint64
		active   bool
	}{
		{"ArbOS 61", true, params.ArbosVersion_61, false},
		{"ArbOS 62", true, params.ArbosVersion_62, true},
		{"ArbOS 63", true, params.ArbosVersion_62 + 1, true},
		{"not Arbitrum", false, params.ArbosVersion_62, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			chainConfig := *params.TestChainConfig
			chainConfig.ArbitrumChainParams = params.ArbitrumChainParams{
				EnableArbOS:         tc.arbitrum,
				InitialArbOSVersion: tc.arbos,
			}
			rules := chainConfig.Rules(big.NewInt(0), false, 0, tc.arbos)
			_, inMap := ActivePrecompiledContracts(rules)[PoseidonPrecompileAddress]
			inList := slices.Contains(ActivePrecompiles(rules), PoseidonPrecompileAddress)
			if inMap != tc.active || inList != tc.active {
				t.Fatalf("in contract map: %v, in address list: %v, want %v", inMap, inList, tc.active)
			}

			statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
			evm := NewEVM(BlockContext{BlockNumber: big.NewInt(0), ArbOSVersion: tc.arbos}, statedb, &chainConfig, Config{})
			ret, left, _, err := evm.StaticCall(caller, PoseidonPrecompileAddress, input, NewGasBudget(gas, 0))
			if err != nil {
				t.Fatal(err)
			}
			used := gas - left.RegularGas
			if !tc.active {
				// A call to an address without code succeeds, returns nothing and is free.
				if len(ret) != 0 || used != 0 {
					t.Fatalf("inactive precompile returned %x and used %d gas", ret, used)
				}
				return
			}
			if !bytes.Equal(ret, want) || used != params.PoseidonHashGas {
				t.Fatalf("got %x for %d gas, want %x for %d gas", ret, used, want, params.PoseidonHashGas)
			}
			// A failing call consumes all the gas it was given.
			ret, left, _, err = evm.StaticCall(caller, PoseidonPrecompileAddress, badInput, NewGasBudget(gas, 0))
			if err == nil || len(ret) != 0 || left.RegularGas != 0 {
				t.Fatalf("bad input: err %v, returned %x, %d gas left", err, ret, left.RegularGas)
			}
		})
	}
}
