package secretsharing

import (
	"testing"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/internal/test"
)

func TestPolyEval(t *testing.T) {
	g := group.P256
	p := polynomial{2, []group.Scalar{
		g.NewScalar(),
		g.NewScalar(),
		g.NewScalar(),
	}}
	p.coeff[0].SetUint64(5)
	p.coeff[1].SetUint64(5)
	p.coeff[2].SetUint64(2)

	x := g.NewScalar()
	x.SetUint64(10)

	got := p.evaluate(x)

	want := g.NewScalar()
	want.SetUint64(255)
	if !got.IsEqual(want) {
		test.ReportError(t, got, want)
	}
}

func TestLagrange(t *testing.T) {
	g := group.P256
	p := polynomial{2, []group.Scalar{
		g.NewScalar(),
		g.NewScalar(),
		g.NewScalar(),
	}}
	p.coeff[0].SetUint64(1234)
	p.coeff[1].SetUint64(166)
	p.coeff[2].SetUint64(94)

	x := []group.Scalar{g.NewScalar(), g.NewScalar(), g.NewScalar()}
	px := []group.Scalar{g.NewScalar(), g.NewScalar(), g.NewScalar()}
	x[0].SetUint64(2)
	px[0].SetUint64(1942)
	x[1].SetUint64(4)
	px[1].SetUint64(3402)
	x[2].SetUint64(5)
	px[2].SetUint64(4414)

	got, err := LagrangeInterpolate(g, x, px)
	test.CheckNoErr(t, err, "failed interpolation")
	want := p.coeff[0]

	if !got.IsEqual(want) {
		test.ReportError(t, got, want)
	}
}
