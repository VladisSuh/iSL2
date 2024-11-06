package main

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

type RSAKeyGenerator struct {
	PrimalityTestType       PrimalityTestType
	MinPrimalityProbability float64
	BitLength               int
}

func NewRSAService(testType PrimalityTestType, minProbability float64, bitLength int) *RSAService {
	keyGen := &RSAKeyGenerator{
		PrimalityTestType:       testType,
		MinPrimalityProbability: minProbability,
		BitLength:               bitLength,
	}
	return &RSAService{
		KeyGenerator: keyGen,
	}
}

func (service *RSAService) GenerateKeys() error {
	p, err := service.KeyGenerator.generatePrime()
	if err != nil {
		return err
	}

	q, err := service.KeyGenerator.generatePrime()
	if err != nil {
		return err
	}

	diff := new(big.Int).Sub(p, q).Abs(new(big.Int).Sub(p, q))
	minDiff := new(big.Int).Lsh(big.NewInt(1), uint(service.KeyGenerator.BitLength/2-100))
	if diff.Cmp(minDiff) < 0 {
		return fmt.Errorf("p и q слишком близки, возможна атака Ферма")
	}

	n := new(big.Int).Mul(p, q)
	phi := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))

	e := big.NewInt(65537)

	gcd := new(big.Int).GCD(nil, nil, e, phi)
	if gcd.Cmp(big.NewInt(1)) != 0 {
		return fmt.Errorf("e и phi не взаимно просты")
	}

	d := new(big.Int).ModInverse(e, phi)
	if d == nil {
		return fmt.Errorf("не удалось вычислить d")
	}

	maxD := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(service.KeyGenerator.BitLength/4)), nil)
	if d.Cmp(maxD) < 0 {
		return fmt.Errorf("d слишком мал, возможна атака Винера")
	}

	service.PublicKey = &PublicKey{N: n, E: e}
	service.PrivateKey = &PrivateKey{N: n, D: d}
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
		return kg.fermatPrimalityTest(n, kg.MinPrimalityProbability)
	case SolovayStrassen:
		return kg.solovayStrassenPrimalityTest(n, kg.MinPrimalityProbability)
	case MillerRabin:
		return kg.millerRabinPrimalityTest(n, kg.MinPrimalityProbability)
	default:
		return false
	}
}

func (kg *RSAKeyGenerator) fermatPrimalityTest(n *big.Int, minProbability float64) bool {
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

func (kg *RSAKeyGenerator) solovayStrassenPrimalityTest(n *big.Int, minProbability float64) bool {
	k := kg.calculateIterations(minProbability)
	one := big.NewInt(1)
	for i := 0; i < k; i++ {
		a, err := rand.Int(rand.Reader, new(big.Int).Sub(n, one))
		if err != nil {
			return false
		}
		a.Add(a, one)

		jacobi := kg.jacobiSymbol(a, n)
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

func (kg *RSAKeyGenerator) millerRabinPrimalityTest(n *big.Int, minProbability float64) bool {
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

func (kg *RSAKeyGenerator) jacobiSymbol(a, n *big.Int) int {
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

func main() {
	rsaService := NewRSAService(MillerRabin, 0.99, 1024)

	fmt.Println("Генерация ключей...")
	err := rsaService.GenerateKeys()
	if err != nil {
		fmt.Printf("Ошибка при генерации ключей: %v\n", err)
		return
	}
	fmt.Println("Ключи сгенерированы успешно.")

	message := big.NewInt(123490)
	fmt.Printf("Оригинальное сообщение: %s\n", message.String())

	ciphertext, err := rsaService.Encrypt(message)
	if err != nil {
		fmt.Printf("Ошибка при шифровании: %v\n", err)
		return
	}
	fmt.Printf("Зашифрованное сообщение: %s\n", ciphertext.String())

	decryptedMessage, err := rsaService.Decrypt(ciphertext)
	if err != nil {
		fmt.Printf("Ошибка при дешифровании: %v\n", err)
		return
	}
	fmt.Printf("Дешифрованное сообщение: %s\n", decryptedMessage.String())

	if message.Cmp(decryptedMessage) == 0 {
		fmt.Println("Успешное шифрование и дешифрование сообщения.")
	} else {
		fmt.Println("Ошибка: исходное и расшифрованное сообщения не совпадают.")
	}
}
