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

package poseidon

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/holiman/uint256"
)

// Known-answer vectors for Poseidon(a, b), all values big-endian hex.
var hashVectors = []struct {
	name, a, b, want string
}{
	{
		// circomlibjs poseidon([1, 1]); light-poseidon 0.4.1 tests/bn254_fq_x5.rs test_poseidon_one.
		name: "circomlibjs [1,1]",
		a:    "0000000000000000000000000000000000000000000000000000000000000001",
		b:    "0000000000000000000000000000000000000000000000000000000000000001",
		want: "007af346e2d304279e79e0a9f3023f771294a78acb70e73f90afe27cad401e81",
	},
	{
		// iden3 go-iden3-crypto poseidon.Hash([1, 2]) =
		// 7853200120776062878684798364095072458815029376092732009249414926327459813530;
		// light-poseidon 0.4.1 test_poseidon_bn254_x5_fq_input_one_two.
		name: "iden3 [1,2]",
		a:    "0000000000000000000000000000000000000000000000000000000000000001",
		b:    "0000000000000000000000000000000000000000000000000000000000000002",
		want: "115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a",
	},
	{
		// light-poseidon 0.4.1 test_poseidon_bn254_x5_fq_input_ones_twos.
		name: "[0x01*32,0x02*32]",
		a:    "0101010101010101010101010101010101010101010101010101010101010101",
		b:    "0202020202020202020202020202020202020202020202020202020202020202",
		want: "0d54e1938f8a8c1c7deb5e0355f26319207b84fe9ca2ce1b26e735c829821990",
	},
	{
		// light-poseidon 0.4.1 test_poseidon_bn254_x5_fq_input_random, second input reduced mod r.
		name: "random",
		a:    "069c6381ac0b968e881c913c17d836067fd15f2cc79f902c8070b36d286617dd",
		b:    "01aa2638aab04754ef1ca09c1dc5b6437c79a0299bffa7e9b09121559c3f3007",
		want: "0a13ad844d3487ad3dbaf3876760eb971283d48333fa5a9e97e6ee422af9554b",
	},
	{
		// Zero inputs: the well-known circom Poseidon(0, 0) Merkle zero leaf.
		name: "[0,0]",
		a:    "0000000000000000000000000000000000000000000000000000000000000000",
		b:    "0000000000000000000000000000000000000000000000000000000000000000",
		want: "2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864",
	},
	{
		// Largest canonical inputs (r-1); computed with an offline reference permutation.
		name: "[r-1,r-1]",
		a:    "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000",
		b:    "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000",
		want: "2c6bd813a6338781378d8706cb82fd4216ab52b752ccd41564d7b98756a6e0fb",
	},
}

func mustInt(t *testing.T, s string) *uint256.Int {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad test hex %q", s)
	}
	return new(uint256.Int).SetBytes32(b)
}

func TestHash2Vectors(t *testing.T) {
	for _, v := range hashVectors {
		got := Hash2(mustInt(t, v.a), mustInt(t, v.b))
		gotBytes := got.Bytes32()
		if hex.EncodeToString(gotBytes[:]) != v.want {
			t.Errorf("%s: got %x, want %s", v.name, gotBytes, v.want)
		}
	}
}

// grain is the Grain LFSR from the Poseidon reference parameter script
// generate_parameters_grain.sage.
type grain struct {
	state [80]byte
}

func newGrain(field, sbox, n, t, rf, rp uint64) *grain {
	var bits []byte
	push := func(v uint64, w int) {
		for i := w - 1; i >= 0; i-- {
			bits = append(bits, byte(v>>uint(i)&1))
		}
	}
	push(field, 2)
	push(sbox, 4)
	push(n, 12)
	push(t, 12)
	push(rf, 10)
	push(rp, 10)
	for range 30 {
		bits = append(bits, 1)
	}
	g := new(grain)
	copy(g.state[:], bits)
	for range 160 {
		g.step()
	}
	return g
}

func (g *grain) step() byte {
	s := &g.state
	b := s[62] ^ s[51] ^ s[38] ^ s[23] ^ s[13] ^ s[0]
	copy(s[:], s[1:])
	s[79] = b
	return b
}

// bits returns the next n output bits (MSB first) after self-shrinking.
func (g *grain) bits(n int) *big.Int {
	v := new(big.Int)
	for range n {
		for {
			b1, b2 := g.step(), g.step()
			if b1 == 1 {
				v.Lsh(v, 1)
				v.SetBit(v, 0, uint(b2))
				break
			}
		}
	}
	return v
}

// TestGrainParameters regenerates the round constants and the MDS matrix with
// the reference script algorithm (field=1, sbox=0, n=254, t=3, R_F=8, R_P=57)
// and checks them against the pinned tables.
func TestGrainParameters(t *testing.T) {
	p := modulus.ToBig()
	g := newGrain(1, 0, 254, width, fullRounds, partialRounds)
	for i := range ark {
		v := g.bits(254)
		for v.Cmp(p) >= 0 {
			v = g.bits(254)
		}
		if v.Cmp(ark[i].ToBig()) != 0 {
			t.Fatalf("round constant %d: got %x, want %x", i, ark[i].ToBig(), v)
		}
	}
	// Cauchy MDS from the first sample: 1 / (x_i + y_j) with distinct x, y.
	var xy [2 * width]*big.Int
	for i := range xy {
		xy[i] = new(big.Int).Mod(g.bits(254), p)
		for j := range i {
			if xy[i].Cmp(xy[j]) == 0 {
				t.Fatal("duplicate Cauchy sample")
			}
		}
	}
	for i := range width {
		for j := range width {
			sum := new(big.Int).Add(xy[i], xy[width+j])
			want := new(big.Int).ModInverse(sum.Mod(sum, p), p)
			if want.Cmp(mds[i][j].ToBig()) != 0 {
				t.Fatalf("mds[%d][%d]: got %x, want %x", i, j, mds[i][j].ToBig(), want)
			}
		}
	}
}

func BenchmarkHash2(b *testing.B) {
	x := uint256.NewInt(1)
	y := uint256.NewInt(2)
	for b.Loop() {
		Hash2(x, y)
	}
}
