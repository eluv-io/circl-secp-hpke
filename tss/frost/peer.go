package frost

import (
	"errors"
	"io"
	"sort"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/group/secretsharing"
)

type PeerSigner struct {
	Suite
	ID       uint16
	keyShare group.Scalar
	myPubKey *PublicKey
}

func (p PeerSigner) Commit(rnd io.Reader) (*Nonce, *Commitment, error) {
	hidingNonce, err := p.Suite.nonceGenerate(rnd, p.keyShare)
	if err != nil {
		return nil, nil, err
	}
	bindingNonce, err := p.Suite.nonceGenerate(rnd, p.keyShare)
	if err != nil {
		return nil, nil, err
	}

	return p.commitWithNonce(hidingNonce, bindingNonce)
}

func (p PeerSigner) commitWithNonce(hidingNonce, bindingNonce group.Scalar) (*Nonce, *Commitment, error) {
	hidingNonceCom := p.Suite.g.NewElement().MulGen(hidingNonce)
	bindingNonceCom := p.Suite.g.NewElement().MulGen(bindingNonce)
	return &Nonce{p.ID, hidingNonce, bindingNonce}, &Commitment{p.ID, hidingNonceCom, bindingNonceCom}, nil
}

func (p PeerSigner) CheckKeyShare(keyShareCommits []KeyShareCommitment) bool {
	return secretsharing.SecretShare{ID: uint(p.ID), Share: p.keyShare}.Verify(p.Suite.g, keyShareCommits)
}

func (p PeerSigner) Public() *PublicKey {
	if p.myPubKey == nil {
		p.myPubKey = &PublicKey{p.Suite, p.Suite.g.NewElement().MulGen(p.keyShare)}
	}
	return p.myPubKey
}

func (p PeerSigner) Sign(msg []byte, pubKey *PublicKey, nonce *Nonce, coms []*Commitment) (*SignShare, error) {
	if p.ID != nonce.ID {
		return nil, errors.New("frost: bad id")
	}
	aux, err := p.Suite.common(uint(p.ID), msg, pubKey, coms)
	if err != nil {
		return nil, err
	}

	tmp := p.Suite.g.NewScalar().Mul(nonce.binding, aux.bindingFactor)
	signShare := p.Suite.g.NewScalar().Add(nonce.hiding, tmp)
	tmp.Mul(aux.lambdaID, p.keyShare)
	tmp.Mul(tmp, aux.challenge)
	signShare.Add(signShare, tmp)

	return &SignShare{ID: p.ID, share: signShare}, nil
}

type SignShare struct {
	ID    uint16
	share group.Scalar
}

func (s *SignShare) Verify(
	suite Suite,
	pubKeySigner *PublicKey,
	comSigner *Commitment,
	coms []*Commitment,
	pubKeyGroup *PublicKey,
	msg []byte,
) bool {
	if s.ID != comSigner.ID || s.ID == 0 {
		return false
	}

	aux, err := suite.common(uint(s.ID), msg, pubKeyGroup, coms)
	if err != nil {
		return false
	}

	comShare := suite.g.NewElement().Mul(coms[aux.idx].binding, aux.bindingFactor)
	comShare.Add(comShare, coms[aux.idx].hiding)

	l := suite.g.NewElement().MulGen(s.share)
	r := suite.g.NewElement().Mul(pubKeySigner.key, suite.g.NewScalar().Mul(aux.challenge, aux.lambdaID))
	r.Add(r, comShare)

	return l.IsEqual(r)
}

type commonAux struct {
	idx           uint
	lambdaID      group.Scalar
	challenge     group.Scalar
	bindingFactor group.Scalar
}

func (s Suite) common(id uint, msg []byte, pubKey *PublicKey, coms []*Commitment) (aux *commonAux, err error) {
	if !sort.SliceIsSorted(coms, func(i, j int) bool { return coms[i].ID < coms[j].ID }) {
		return nil, errors.New("frost:commitments must be sorted")
	}

	idx := sort.Search(len(coms), func(j int) bool { return uint(coms[j].ID) >= id })
	if !(idx < len(coms) && uint(coms[idx].ID) == id) {
		return nil, errors.New("frost: commitment not present")
	}

	bindingFactors, err := s.getBindingFactors(coms, msg)
	if err != nil {
		return nil, err
	}

	bindingFactor, err := s.getBindingFactorFromID(bindingFactors, id)
	if err != nil {
		return nil, err
	}

	groupCom, err := s.getGroupCommitment(coms, bindingFactors)
	if err != nil {
		return nil, err
	}

	challenge, err := s.getChallenge(groupCom, pubKey, msg)
	if err != nil {
		return nil, err
	}

	peers := make([]group.Scalar, len(coms))
	for i := range coms {
		peers[i] = s.g.NewScalar()
		peers[i].SetUint64(uint64(coms[i].ID))
	}
	lambdaID := secretsharing.LagrangeCoefficient(s.g, peers, uint(idx))

	return &commonAux{
		idx:           uint(idx),
		lambdaID:      lambdaID,
		challenge:     challenge,
		bindingFactor: bindingFactor,
	}, nil
}
