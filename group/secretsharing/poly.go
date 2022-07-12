package secretsharing

import (
	"errors"
	"io"

	"github.com/cloudflare/circl/group"
)

type polynomial struct {
	deg   uint
	coeff []group.Scalar
}

func randomPolynomial(rnd io.Reader, g group.Group, deg uint) (p polynomial) {
	p = polynomial{deg, make([]group.Scalar, deg+1)}

	for i := 0; i <= int(deg); i++ {
		p.coeff[i] = g.RandomScalar(rnd)
	}
	return
}

func (p polynomial) evaluate(x group.Scalar) group.Scalar {
	px := p.coeff[p.deg].Copy()
	for i := int(p.deg) - 1; i >= 0; i-- {
		px.Mul(px, x)
		px.Add(px, p.coeff[i])
	}
	return px
}

func LagrangeCoefficient(g group.Group, x []group.Scalar, index uint) group.Scalar {
	if int(index) > len(x) {
		panic("invalid parameter")
	}

	num := g.NewScalar()
	num.SetUint64(1)
	den := g.NewScalar()
	den.SetUint64(1)
	tmp := g.NewScalar()

	for j := range x {
		if j != int(index) {
			num.Mul(num, x[j])
			den.Mul(den, tmp.Sub(x[j], x[index]))
		}
	}

	return num.Mul(num, tmp.Inv(den))
}

func LagrangeInterpolate(g group.Group, x, px []group.Scalar) (group.Scalar, error) {
	if len(x) != len(px) {
		return nil, errors.New("lagrange: bad input length")
	}

	zero := g.NewScalar()
	for i := range x {
		if x[i].IsEqual(zero) {
			return nil, errors.New("lagrange: tried to evaluate on zero")
		}
	}

	pol0 := g.NewScalar()
	delta := g.NewScalar()
	for i := range x {
		pol0.Add(pol0, delta.Mul(px[i], LagrangeCoefficient(g, x, uint(i))))
	}

	return pol0, nil
}
