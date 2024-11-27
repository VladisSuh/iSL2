package Task1_3

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
)

type PrimalityTestType int

const (
	Fermat PrimalityTestType = iota
	SolovayStrassen
	MillerRabin
)

type RSAService struct {
	KeyGenerator *RSAKeyGenerator
	PublicKey    *PublicKey
	PrivateKey   *PrivateKey
}

type PublicKey struct {
	N *big.Int
	E *big.Int
}

type PrivateKey struct {
	N *big.Int
	D *big.Int
}

type VulnerabilityType int

const (
	None VulnerabilityType = iota
	FermatVulnerability
	WienerVulnerability
)

type RSAKeyGenerator struct {
	PrimalityTestType       PrimalityTestType
	MinPrimalityProbability float64
	BitLength               int
	VulnerabilityType       VulnerabilityType
}

func NewRSAService(testType PrimalityTestType, minProbability float64, bitLength int, vulnerabilityType VulnerabilityType) *RSAService {
	keyGen := &RSAKeyGenerator{
		PrimalityTestType:       testType,
		MinPrimalityProbability: minProbability,
		BitLength:               bitLength,
		VulnerabilityType:       vulnerabilityType,
	}
	return &RSAService{
		KeyGenerator: keyGen,
	}
}

func (service *RSAService) GenerateKeys() error {
	var p, q, d, e *big.Int
	var err error

	for {
		p, err = service.KeyGenerator.generatePrime()
		if err != nil {
			return err
		}

		if service.KeyGenerator.VulnerabilityType == FermatVulnerability {
			delta := new(big.Int).SetBit(big.NewInt(0), service.KeyGenerator.BitLength/2-10, 1) // delta = 2^(bitLength/2 - 10)
			q = new(big.Int).Add(p, delta)
			if !service.KeyGenerator.isPrime(q) {
				continue
			}
		} else {
			q, err = service.KeyGenerator.generatePrime()
			if err != nil {
				return err
			}
			diff := new(big.Int).Abs(new(big.Int).Sub(p, q))
			minDiff := new(big.Int).Lsh(big.NewInt(1), uint(service.KeyGenerator.BitLength/2-100))
			if diff.Cmp(minDiff) < 0 {
				continue
			}
		}

		n := new(big.Int).Mul(p, q)
		phi := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))

		if service.KeyGenerator.VulnerabilityType == WienerVulnerability {
			dLimit := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(service.KeyGenerator.BitLength/16)), nil)
			for {
				d, err = rand.Int(rand.Reader, dLimit)
				if err != nil {
					return err
				}
				if d.Cmp(big.NewInt(2)) < 0 {
					continue
				}
				gcd := new(big.Int).GCD(nil, nil, d, phi)
				if gcd.Cmp(big.NewInt(1)) == 0 {
					break
				}
			}
			e = new(big.Int).ModInverse(d, phi)
			if e == nil || e.Cmp(big.NewInt(1)) <= 0 || e.Cmp(phi) >= 0 {
				continue
			}
		} else {
			e = big.NewInt(65537)
			gcd := new(big.Int).GCD(nil, nil, e, phi)
			if gcd.Cmp(big.NewInt(1)) != 0 {
				continue
			}
			d = new(big.Int).ModInverse(e, phi)
			if d == nil {
				continue
			}
			// Проверка на атаку Винера
			maxD := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(service.KeyGenerator.BitLength/4)), nil)
			if d.Cmp(maxD) < 0 {
				continue
			}
		}

		service.PublicKey = &PublicKey{N: n, E: e}
		service.PrivateKey = &PrivateKey{N: n, D: d}
		break
	}

	return nil
}

func (service *RSAService) Encrypt(message *big.Int) (*big.Int, error) {
	if service.PublicKey == nil {
		return nil, fmt.Errorf("публичный ключ не инициализирован")
	}
	if message.Cmp(service.PublicKey.N) >= 0 {
		return nil, fmt.Errorf("сообщение должно быть меньше модуля N")
	}
	cipher := new(big.Int).Exp(message, service.PublicKey.E, service.PublicKey.N)
	return cipher, nil
}

func (service *RSAService) Decrypt(ciphertext *big.Int) (*big.Int, error) {
	if service.PrivateKey == nil {
		return nil, fmt.Errorf("приватный ключ не инициализирован")
	}
	message := new(big.Int).Exp(ciphertext, service.PrivateKey.D, service.PrivateKey.N)
	return message, nil
}

func (kg *RSAKeyGenerator) generatePrime() (*big.Int, error) {
	var prime *big.Int
	var err error
	for {
		prime, err = rand.Prime(rand.Reader, kg.BitLength/2)
		if err != nil {
			return nil, err
		}
		if kg.isPrime(prime) {
			break
		}
	}
	return prime, nil
}

func (kg *RSAKeyGenerator) isPrime(n *big.Int) bool {
	switch kg.PrimalityTestType {
	case Fermat:
		return kg.FermatPrimalityTest(n, kg.MinPrimalityProbability)
	case SolovayStrassen:
		return kg.SolovayStrassenPrimalityTest(n, kg.MinPrimalityProbability)
	case MillerRabin:
		return kg.MillerRabinPrimalityTest(n, kg.MinPrimalityProbability)
	default:
		return false
	}
}

func (kg *RSAKeyGenerator) FermatPrimalityTest(n *big.Int, minProbability float64) bool {
	k := kg.calculateIterations(minProbability)
	one := big.NewInt(1)
	for i := 0; i < k; i++ {
		a, err := rand.Int(rand.Reader, new(big.Int).Sub(n, one))
		if err != nil {
			return false
		}
		a.Add(a, one)
		result := new(big.Int).Exp(a, new(big.Int).Sub(n, one), n)
		if result.Cmp(one) != 0 {
			return false
		}
	}
	return true
}

func (kg *RSAKeyGenerator) SolovayStrassenPrimalityTest(n *big.Int, minProbability float64) bool {
	k := kg.calculateIterations(minProbability)
	one := big.NewInt(1)
	for i := 0; i < k; i++ {
		a, err := rand.Int(rand.Reader, new(big.Int).Sub(n, one))
		if err != nil {
			return false
		}
		a.Add(a, one)

		jacobi := kg.JacobiSymbol(a, n)
		if jacobi == 0 {
			return false
		}
		exponent := new(big.Int).Div(new(big.Int).Sub(n, one), big.NewInt(2))
		modExp := new(big.Int).Exp(a, exponent, n)
		jacobiBig := big.NewInt(int64(jacobi))
		if jacobiBig.Cmp(modExp) != 0 && jacobiBig.Mod(jacobiBig, n).Cmp(modExp) != 0 {
			return false
		}
	}
	return true
}

func (kg *RSAKeyGenerator) MillerRabinPrimalityTest(n *big.Int, minProbability float64) bool {
	k := kg.calculateIterations(minProbability)
	one := big.NewInt(1)
	d := new(big.Int).Sub(n, one)
	s := 0
	for d.Bit(0) == 0 {
		d.Rsh(d, 1)
		s++
	}
	for i := 0; i < k; i++ {
		a, err := rand.Int(rand.Reader, new(big.Int).Sub(n, big.NewInt(3)))
		if err != nil {
			return false
		}
		a.Add(a, big.NewInt(2))

		x := new(big.Int).Exp(a, d, n)
		if x.Cmp(one) == 0 || x.Cmp(new(big.Int).Sub(n, one)) == 0 {
			continue
		}
		for r := 1; r < s; r++ {
			x.Exp(x, big.NewInt(2), n)
			if x.Cmp(one) == 0 {
				return false
			}
			if x.Cmp(new(big.Int).Sub(n, one)) == 0 {
				break
			}
		}
		if x.Cmp(new(big.Int).Sub(n, one)) != 0 {
			return false
		}
	}
	return true
}

func (kg *RSAKeyGenerator) calculateIterations(minProbability float64) int {
	if minProbability <= 0.5 {
		return 1
	}
	return int(math.Ceil(math.Log(1.0-minProbability) / math.Log(0.5)))
}

func (kg *RSAKeyGenerator) JacobiSymbol(a, n *big.Int) int {
	result := 1
	a = new(big.Int).Mod(a, n)
	for a.Cmp(big.NewInt(0)) != 0 {
		for a.Bit(0) == 0 {
			a.Rsh(a, 1)
			r := new(big.Int).Mod(n, big.NewInt(8)).Int64()
			if r == 3 || r == 5 {
				result = -result
			}
		}
		a, n = n, a
		if a.Int64()%4 == 3 && n.Int64()%4 == 3 {
			result = -result
		}
		a = new(big.Int).Mod(a, n)
	}
	if n.Cmp(big.NewInt(1)) == 0 {
		return result
	}
	return 0
}
