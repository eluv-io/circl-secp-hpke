// Package frost provides the frost threshold signature scheme for Schnorr signatures.
//
// References:
//  frost paper: https://eprint.iacr.org/2020/852
//  draft-irtf-cfrg-frost: https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost
package frost

import (
	"io"

	"github.com/cloudflare/circl/group"
)

type PrivateKey struct {
	Suite
	key    group.Scalar
	pubKey *PublicKey
}

type PublicKey struct {
	Suite
	key group.Element
}

func GenerateKey(s Suite, rnd io.Reader) *PrivateKey {
	return &PrivateKey{s, s.g.RandomNonZeroScalar(rnd), nil}
}

func (k *PrivateKey) Public() *PublicKey {
	return &PublicKey{k.Suite, k.Suite.g.NewElement().MulGen(k.key)}
}

func Verify(s Suite, pubKey *PublicKey, msg, signature []byte) bool {
	params := s.g.Params()
	Ne, Ns := params.CompressedElementLength, params.ScalarLength
	if len(signature) < int(Ne+Ns) {
		return false
	}

	REnc := signature[:Ne]
	R := s.g.NewElement()
	err := R.UnmarshalBinary(REnc)
	if err != nil {
		return false
	}

	zEnc := signature[Ne : Ne+Ns]
	z := s.g.NewScalar()
	err = z.UnmarshalBinary(zEnc)
	if err != nil {
		return false
	}

	pubKeyEnc, err := pubKey.key.MarshalBinaryCompress()
	if err != nil {
		return false
	}

	chInput := append(append(append([]byte{}, REnc...), pubKeyEnc...), msg...)
	c := s.hasher.h2(chInput)

	l := s.g.NewElement().MulGen(z)
	r := s.g.NewElement().Mul(pubKey.key, c)
	r.Add(r, R)

	return l.IsEqual(r)
}
