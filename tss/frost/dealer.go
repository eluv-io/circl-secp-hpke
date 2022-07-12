package frost

import (
	"errors"
	"io"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/group/secretsharing"
)

type Dealer struct {
	Suite
	threshold  uint
	maxSigners uint
	vss        *secretsharing.FeldmanSS
}

func NewDealer(s Suite, threshold, maxSigners uint) (*Dealer, error) {
	if threshold > maxSigners {
		return nil, errors.New("frost: invalid parameters")
	}

	vss, err := secretsharing.NewVerifiable(s.g, threshold, maxSigners)
	if err != nil {
		return nil, err
	}

	return &Dealer{Suite: s, threshold: threshold, maxSigners: maxSigners, vss: vss}, nil
}

type KeyShareCommitment = group.Element

func (d Dealer) Deal(rnd io.Reader, privKey *PrivateKey) ([]PeerSigner, []KeyShareCommitment) {
	shares, coms := d.vss.ShardSecret(rnd, privKey.key)

	peers := make([]PeerSigner, d.maxSigners)
	for i := range shares {
		peers[i] = PeerSigner{
			Suite:    d.Suite,
			ID:       uint16(shares[i].ID),
			keyShare: shares[i].Share,
			myPubKey: nil,
		}
	}

	shareComs := make([]KeyShareCommitment, d.threshold+1)
	copy(shareComs, coms)

	return peers, shareComs
}
