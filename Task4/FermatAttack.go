package Task4

import (
	"fmt"
	"iSL2/Task1_3"
	"math/big"
)

type FermatAttackService struct{}

func (fas *FermatAttackService) Attack(pubKey Task1_3.PublicKey) (*big.Int, *big.Int, error) {
	N := pubKey.N
	a := new(big.Int).Sqrt(N)
	one := big.NewInt(1)
	a.Add(a, one)

	for {
		bSquared := new(big.Int).Mul(a, a)
		bSquared.Sub(bSquared, N)
		bRoot := new(big.Int).Sqrt(bSquared)
		if new(big.Int).Mul(bRoot, bRoot).Cmp(bSquared) == 0 {
			p := new(big.Int).Sub(a, bRoot)
			q := new(big.Int).Add(a, bRoot)
			phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
			d := new(big.Int).ModInverse(pubKey.E, phi)
			if d == nil {
				return nil, nil, fmt.Errorf("не удалось вычислить d")
			}
			return d, phi, nil
		}
		a.Add(a, one)
		if a.Cmp(new(big.Int).Add(N, big.NewInt(1000))) > 0 {
			return nil, nil, fmt.Errorf("не удалось факторизовать N с помощью атаки Ферма")
		}
	}
}
