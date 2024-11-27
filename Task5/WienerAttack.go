package Task5

import (
	"fmt"
	"iSL2/Task1_3"
	"math/big"
)

type WienerAttackService struct{}

type Convergent struct {
	K *big.Int
	D *big.Int
}

func (was *WienerAttackService) Attack(pubKey *Task1_3.PublicKey) (*big.Int, *big.Int, []Convergent, error) {
	e := pubKey.E
	N := pubKey.N

	convergents := was.continuedFraction(e, N)

	for _, conv := range convergents {
		k := conv.K
		d := conv.D

		if k.Sign() == 0 || d.Sign() == 0 {
			continue
		}

		phi, err := was.checkConvergent(e, N, k, d)
		if err == nil {
			return d, phi, convergents, nil
		}
	}

	return nil, nil, convergents, fmt.Errorf("не удалось найти приватный ключ с помощью атаки Винера")
}

func (was *WienerAttackService) continuedFraction(e, N *big.Int) []Convergent {
	var convergents []Convergent
	var quotients []*big.Int

	a := e
	b := N
	zero := big.NewInt(0)

	for b.Cmp(zero) != 0 {
		q := new(big.Int).Div(a, b)
		r := new(big.Int).Mod(a, b)
		quotients = append(quotients, q)
		a = b
		b = r
	}

	numPrev := big.NewInt(0)
	numCurr := big.NewInt(1)
	denPrev := big.NewInt(1)
	denCurr := big.NewInt(0)

	for _, q := range quotients {
		numNext := new(big.Int).Add(new(big.Int).Mul(q, numCurr), numPrev)
		denNext := new(big.Int).Add(new(big.Int).Mul(q, denCurr), denPrev)

		convergents = append(convergents, Convergent{K: numNext, D: denNext})

		numPrev = numCurr
		numCurr = numNext
		denPrev = denCurr
		denCurr = denNext
	}

	return convergents
}

func (was *WienerAttackService) checkConvergent(e, N, k, d *big.Int) (*big.Int, error) {
	one := big.NewInt(1)
	edMinus1 := new(big.Int).Sub(new(big.Int).Mul(e, d), one)
	if new(big.Int).Mod(edMinus1, k).Cmp(big.NewInt(0)) != 0 {
		return nil, fmt.Errorf("ed - 1 не кратно k")
	}
	phi := new(big.Int).Div(edMinus1, k)

	s := new(big.Int).Add(new(big.Int).Sub(N, phi), one)

	discrim := new(big.Int).Sub(new(big.Int).Mul(s, s), new(big.Int).Mul(big.NewInt(4), N))
	if discrim.Sign() < 0 {
		return nil, fmt.Errorf("дискриминант отрицательный")
	}

	sqrtDiscrim := new(big.Int).Sqrt(discrim)
	if new(big.Int).Mul(sqrtDiscrim, sqrtDiscrim).Cmp(discrim) != 0 {
		return nil, fmt.Errorf("дискриминант не является полным квадратом")
	}

	x1 := new(big.Int).Div(new(big.Int).Add(s, sqrtDiscrim), big.NewInt(2))
	x2 := new(big.Int).Div(new(big.Int).Sub(s, sqrtDiscrim), big.NewInt(2))

	if new(big.Int).Mul(x1, x2).Cmp(N) != 0 {
		return nil, fmt.Errorf("корни не подходят")
	}

	return phi, nil
}

func (was *WienerAttackService) isqrt(n *big.Int) *big.Int {
	two := big.NewInt(2)
	x := new(big.Int).Rsh(n, uint(n.BitLen()/2))
	y := new(big.Int)
	for {
		y.Div(n, x)
		y.Add(y, x)
		y.Div(y, two)
		if y.Cmp(x) >= 0 {
			return x
		}
		x.Set(y)
	}
}
