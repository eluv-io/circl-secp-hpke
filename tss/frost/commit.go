package frost

import (
	"encoding/binary"
	"errors"
	"io"
	"sort"

	"github.com/cloudflare/circl/group"
)

type Nonce struct {
	ID              uint16
	hiding, binding group.Scalar
}

func (s Suite) nonceGenerate(rnd io.Reader, secret group.Scalar) (group.Scalar, error) {
	k := make([]byte, 32)
	_, err := io.ReadFull(rnd, k)
	if err != nil {
		return nil, err
	}
	secretEnc, err := secret.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return s.hasher.h4(append(append([]byte{}, k...), secretEnc...)), nil
}

type Commitment struct {
	ID              uint16
	hiding, binding group.Element
}

func (c Commitment) MarshalBinary() ([]byte, error) {
	bytes := (&[2]byte{})[:]
	binary.BigEndian.PutUint16(bytes, c.ID)

	h, err := c.hiding.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}
	b, err := c.binding.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}

	return append(append(bytes, h...), b...), nil
}

func encodeComs(coms []*Commitment) ([]byte, error) {
	sort.SliceStable(coms, func(i, j int) bool { return coms[i].ID < coms[j].ID })

	var out []byte
	for i := range coms {
		cEnc, err := coms[i].MarshalBinary()
		if err != nil {
			return nil, err
		}
		out = append(out, cEnc...)
	}
	return out, nil
}

type bindingFactor struct {
	ID     uint16
	factor group.Scalar
}

func (s Suite) getBindingFactorFromID(bindingFactors []bindingFactor, id uint) (group.Scalar, error) {
	for i := range bindingFactors {
		if uint(bindingFactors[i].ID) == id {
			return bindingFactors[i].factor, nil
		}
	}
	return nil, errors.New("frost: id not found")
}

func (s Suite) getBindingFactors(coms []*Commitment, msg []byte) ([]bindingFactor, error) {
	msgHash := s.hasher.h3(msg)
	commitEncoded, err := encodeComs(coms)
	if err != nil {
		return nil, err
	}
	commitEncodedHash := s.hasher.h3(commitEncoded)
	rhoInputPrefix := append(append([]byte{}, msgHash...), commitEncodedHash...)

	bindingFactors := make([]bindingFactor, len(coms))
	id := (&[2]byte{})[:]
	for i := range coms {
		binary.BigEndian.PutUint16(id, coms[i].ID)
		bf := s.hasher.h1(append(append([]byte{}, rhoInputPrefix...), id...))
		bindingFactors[i] = bindingFactor{ID: coms[i].ID, factor: bf}
	}

	return bindingFactors, nil
}

func (s Suite) getGroupCommitment(coms []*Commitment, bindingFactors []bindingFactor) (group.Element, error) {
	gc := s.g.NewElement()
	tmp := s.g.NewElement()
	for i := range coms {
		bf, err := s.getBindingFactorFromID(bindingFactors, uint(coms[i].ID))
		if err != nil {
			return nil, err
		}
		tmp.Mul(coms[i].binding, bf)
		tmp.Add(tmp, coms[i].hiding)
		gc.Add(gc, tmp)
	}

	return gc, nil
}

func (s Suite) getChallenge(groupCom group.Element, pubKey *PublicKey, msg []byte) (group.Scalar, error) {
	gcEnc, err := groupCom.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}
	pkEnc, err := pubKey.key.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}
	chInput := append(append(append([]byte{}, gcEnc...), pkEnc...), msg...)

	return s.hasher.h2(chInput), nil
}
