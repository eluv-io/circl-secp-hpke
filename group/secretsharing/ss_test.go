package secretsharing_test

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/group/secretsharing"
	"github.com/cloudflare/circl/internal/test"
)

func TestShamirSS(tt *testing.T) {
	g := group.P256
	t := uint(3)
	n := uint(5)

	s, err := secretsharing.New(g, t, n)
	test.CheckNoErr(tt, err, "failed to create ShamirSS")

	want := g.RandomScalar(rand.Reader)
	shares := s.ShardSecret(rand.Reader, want)
	test.CheckOk(len(shares) == int(n), "bad num shares", tt)

	// Test any possible subset size.
	for k := 0; k < int(n); k++ {
		got, err := s.RecoverSecret(shares[:k])
		if k <= int(t) {
			test.CheckIsErr(tt, err, "should not recover secret")
			test.CheckOk(got == nil, "not nil secret", tt)
		} else {
			test.CheckNoErr(tt, err, "should recover secret")
			if !got.IsEqual(want) {
				test.ReportError(tt, got, want, t, k, n)
			}
		}
	}
}

func TestFeldmanSS(tt *testing.T) {
	g := group.P256
	t := uint(3)
	n := uint(5)

	vs, err := secretsharing.NewVerifiable(g, t, n)
	test.CheckNoErr(tt, err, "failed to create ShamirSS")

	want := g.RandomScalar(rand.Reader)
	shares, com := vs.ShardSecret(rand.Reader, want)
	test.CheckOk(len(shares) == int(n), "bad num shares", tt)
	test.CheckOk(len(com) == int(t+1), "bad num commitments", tt)

	for i := range shares {
		test.CheckOk(shares[i].Verify(g, com), "failed one share", tt)
	}

	// Test any possible subset size.
	for k := 0; k < int(n); k++ {
		got, err := vs.RecoverSecret(shares[:k])
		if k <= int(t) {
			test.CheckIsErr(tt, err, "should not recover secret")
			test.CheckOk(got == nil, "not nil secret", tt)
		} else {
			test.CheckNoErr(tt, err, "should recover secret")
			if !got.IsEqual(want) {
				test.ReportError(tt, got, want, t, k, n)
			}
		}
	}
}

func BenchmarkShamirSS(b *testing.B) {
	g := group.P256
	t := uint(3)
	n := uint(5)

	s, _ := secretsharing.New(g, t, n)
	want := g.RandomScalar(rand.Reader)
	shares := s.ShardSecret(rand.Reader, want)

	b.Run("Shard", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			s.ShardSecret(rand.Reader, want)
		}
	})

	b.Run("Recover", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = s.RecoverSecret(shares)
		}
	})
}

func BenchmarkFeldmanSS(b *testing.B) {
	g := group.P256
	t := uint(3)
	n := uint(5)

	s, _ := secretsharing.NewVerifiable(g, t, n)
	want := g.RandomScalar(rand.Reader)
	shares, com := s.ShardSecret(rand.Reader, want)

	b.Run("Shard", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			s.ShardSecret(rand.Reader, want)
		}
	})

	b.Run("Recover", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = s.RecoverSecret(shares)
		}
	})

	b.Run("Verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			shares[0].Verify(g, com)
		}
	})
}
