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
	"math"
	"math/big"
	"math/rand/v2"
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
		// Largest canonical inputs (r-1); go-iden3-crypto v2.0.0 poseidon.Hash.
		name: "[r-1,r-1]",
		a:    "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000",
		b:    "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000",
		want: "2c6bd813a6338781378d8706cb82fd4216ab52b752ccd41564d7b98756a6e0fb",
	},
	{
		// Swapped [1,2]: the hash is not symmetric; go-iden3-crypto v2.0.0 poseidon.Hash.
		name: "[2,1]",
		a:    "0000000000000000000000000000000000000000000000000000000000000002",
		b:    "0000000000000000000000000000000000000000000000000000000000000001",
		want: "1576c555b70c9b778666e91d600fdc6d73f30aeed2f6adc5360d6a052259775a",
	},
	{
		// go-iden3-crypto v2.0.0 poseidon.Hash.
		name: "[0,r-1]",
		a:    "0000000000000000000000000000000000000000000000000000000000000000",
		b:    "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000",
		want: "28b2de3348b15076cbe645321cd2abbd0d2812669574ed4d5f978fe4e7de98bc",
	},
	{
		// go-iden3-crypto v2.0.0 poseidon.Hash.
		name: "[r-1,0]",
		a:    "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000",
		b:    "0000000000000000000000000000000000000000000000000000000000000000",
		want: "1b694eae0d9995b3dd1f09a0f15f950cfb003d1bd4e8b68d3285a3a8fe319438",
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

// refHash2 is a math/big transcription of the permutation. It shares the
// parameter tables with Hash2 but none of its uint256 arithmetic.
func refHash2(a, b *big.Int) *big.Int {
	p := modulus.ToBig()
	five := big.NewInt(5)
	state := [width]*big.Int{new(big.Int), new(big.Int).Set(a), new(big.Int).Set(b)}
	for r := range rounds {
		full := r < fullRounds/2 || r >= fullRounds/2+partialRounds
		for i := range state {
			state[i].Add(state[i], ark[r*width+i].ToBig())
			if full || i == 0 {
				state[i].Exp(state[i], five, p)
			}
		}
		var next [width]*big.Int
		for i := range next {
			next[i] = new(big.Int)
			for j := range state {
				next[i].Add(next[i], new(big.Int).Mul(mds[i][j].ToBig(), state[j]))
			}
			next[i].Mod(next[i], p)
		}
		state = next
	}
	return state[0]
}

// TestHash2Reference compares Hash2 with refHash2 on limb-boundary values and
// on pseudo-random field elements, and checks that Hash2 leaves its inputs
// untouched, also when both arguments are the same pointer.
func TestHash2Reference(t *testing.T) {
	check := func(a, b *uint256.Int) {
		t.Helper()
		a0, b0 := *a, *b
		got := Hash2(a, b)
		if *a != a0 || *b != b0 {
			t.Fatalf("Hash2(%s, %s) modified its inputs", a0.Hex(), b0.Hex())
		}
		if want := refHash2(a.ToBig(), b.ToBig()); got.ToBig().Cmp(want) != 0 {
			t.Fatalf("Hash2(%s, %s): got %s, want %x", a.Hex(), b.Hex(), got.Hex(), want)
		}
	}
	pow2 := func(n uint) *uint256.Int { return new(uint256.Int).Lsh(uint256.NewInt(1), n) }
	edges := []*uint256.Int{
		uint256.NewInt(0), uint256.NewInt(1), uint256.NewInt(2),
		new(uint256.Int).SubUint64(modulus, 1), new(uint256.Int).SubUint64(modulus, 2),
		new(uint256.Int).Rsh(modulus, 1),
		uint256.NewInt(math.MaxUint64), pow2(64), pow2(128), pow2(192), pow2(253),
	}
	for _, a := range edges {
		for _, b := range edges {
			check(a, b)
		}
	}
	rng := rand.New(rand.NewPCG(1, 2))
	random := func() *uint256.Int {
		x := &uint256.Int{rng.Uint64(), rng.Uint64(), rng.Uint64(), rng.Uint64()}
		return x.Mod(x, modulus)
	}
	for range 1000 {
		check(random(), random())
	}
}

func TestIsCanonical(t *testing.T) {
	for _, tc := range []struct {
		x    *uint256.Int
		want bool
	}{
		{uint256.NewInt(0), true},
		{new(uint256.Int).SubUint64(modulus, 1), true},
		{modulus, false},
		{new(uint256.Int).AddUint64(modulus, 1), false},
		{new(uint256.Int).SetAllOne(), false},
	} {
		if got := IsCanonical(tc.x); got != tc.want {
			t.Errorf("IsCanonical(%s) = %v, want %v", tc.x.Hex(), got, tc.want)
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
