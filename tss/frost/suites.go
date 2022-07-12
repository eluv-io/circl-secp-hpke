package frost

import (
	"crypto"
	_ "crypto/sha256"
	"crypto/sha512"
	"fmt"

	r255 "github.com/bwesterb/go-ristretto"
	"github.com/cloudflare/circl/group"
)

var (
	P256         = Suite{group.P256, suiteP{group.P256, crypto.SHA256, "FROST-P256-SHA256-v5"}}
	Ristretto255 = Suite{group.Ristretto255, suiteRis255{"FROST-RISTRETTO255-SHA512-v5"}}
)

type Suite struct {
	g      group.Group
	hasher interface {
		h1(m []byte) group.Scalar
		h2(m []byte) group.Scalar
		h4(m []byte) group.Scalar
		h3(m []byte) []byte
	}
}

func (s Suite) String() string { return s.hasher.(fmt.Stringer).String() }

const (
	labelRho    = "rho"
	labelChal   = "chal"
	labelNonce  = "nonce"
	labelDigest = "digest"
)

type suiteP struct {
	g       group.Group
	hash    crypto.Hash
	context string
}

func (s suiteP) String() string           { return s.context[:len(s.context)-3] }
func (s suiteP) h1(m []byte) group.Scalar { return s.g.HashToScalar(m, []byte(s.context+labelRho)) }
func (s suiteP) h2(m []byte) group.Scalar { return s.g.HashToScalar(m, []byte(s.context+labelChal)) }
func (s suiteP) h4(m []byte) group.Scalar { return s.g.HashToScalar(m, []byte(s.context+labelNonce)) }
func (s suiteP) h3(m []byte) []byte {
	H := s.hash.New()
	_, _ = H.Write([]byte(s.context + labelDigest))
	_, _ = H.Write(m)
	return H.Sum(nil)
}

type suiteRis255 struct {
	context string
}

func (s suiteRis255) String() string { return s.context[:len(s.context)-3] }

func (s suiteRis255) hashLabeled(m []byte, label string) (sum [64]byte) {
	H := sha512.New()
	_, _ = H.Write([]byte(s.context + label))
	_, _ = H.Write(m)
	copy(sum[:], H.Sum(nil))

	return
}

func (s suiteRis255) getScalar(data [64]byte) group.Scalar {
	var y r255.Scalar
	y.SetReduced(&data)
	bytes, _ := y.MarshalBinary()
	z := group.Ristretto255.NewScalar()
	_ = z.UnmarshalBinary(bytes)
	return z
}

func (s suiteRis255) h1(m []byte) group.Scalar { return s.getScalar(s.hashLabeled(m, labelRho)) }
func (s suiteRis255) h2(m []byte) group.Scalar { return s.getScalar(s.hashLabeled(m, labelChal)) }
func (s suiteRis255) h4(m []byte) group.Scalar { return s.getScalar(s.hashLabeled(m, labelNonce)) }
func (s suiteRis255) h3(m []byte) []byte       { d := s.hashLabeled(m, labelDigest); return d[:] }
