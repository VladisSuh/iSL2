package main

import (
	"bufio"
	"fmt"
	"iSL2/Task1_3"
	"iSL2/Task4"
	"iSL2/Task5"
	"math/big"
	"os"
	"strings"
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("Выберите режим работы программы (RSA(1), атака Ферма(2), атака Винера(3)):")
	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Ошибка чтения ввода:", err)
		return
	}

	input = strings.TrimSpace(input)

	handleCase(input)

}

func handleCase(value string) {
	switch value {
	case "1":
		rsaService := Task1_3.NewRSAService(Task1_3.MillerRabin, 0.99, 1024, Task1_3.None)

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
	case "2":
		rsaService := Task1_3.NewRSAService(Task1_3.MillerRabin, 0.99, 64, Task1_3.FermatVulnerability)

		fmt.Println("Генерация уязвимых ключей...")
		err := rsaService.GenerateKeys()
		if err != nil {
			fmt.Printf("Ошибка при генерации ключей: %v\n", err)
			return
		}
		fmt.Println("Ключи сгенерированы успешно.")

		attackService := &Task4.FermatAttackService{}
		fmt.Println("Выполнение атаки Ферма...")
		d, phi, err := attackService.Attack(*rsaService.PublicKey)
		if err != nil {
			fmt.Printf("Атака не удалась: %v\n", err)
			return
		}
		fmt.Println("Атака успешна")
		fmt.Printf("Найденное значение d: %s\n", d.String())
		fmt.Printf("Значение функции Эйлера φ(N): %s\n", phi.String())

		if d.Cmp(rsaService.PrivateKey.D) == 0 {
			fmt.Println("Найденное значение d совпадает с оригинальным!")
		} else {
			fmt.Println("Найденное значение d не совпадает с оригинальным.")
		}

		message := big.NewInt(12345)
		ciphertext, err := rsaService.Encrypt(message)
		if err != nil {
			fmt.Printf("Ошибка при шифровании: %v\n", err)
			return
		}

		decryptedMessage := new(big.Int).Exp(ciphertext, d, rsaService.PublicKey.N)
		fmt.Printf("Дешифрованное сообщение с найденным d: %s\n", decryptedMessage.String())

		if message.Cmp(decryptedMessage) == 0 {
			fmt.Println("Успешно расшифровано с найденным d.")
		} else {
			fmt.Println("Не удалось расшифровать с найденным d.")
		}
	case "3":
		rsaService := Task1_3.NewRSAService(Task1_3.MillerRabin, 0.99, 512, Task1_3.WienerVulnerability)

		fmt.Println("Генерация ключей с маленьким d...")
		err := rsaService.GenerateKeys()
		if err != nil {
			fmt.Printf("Ошибка при генерации ключей: %v\n", err)
			return
		}
		fmt.Println("Ключи сгенерированы успешно.")

		attackService := &Task5.WienerAttackService{}
		fmt.Println("Выполнение атаки Винера...")
		dRecovered, phi, convergents, err := attackService.Attack(rsaService.PublicKey)
		if err != nil {
			fmt.Printf("Атака не удалась: %v\n", err)
			return
		}
		fmt.Println("Атака успешна")
		fmt.Printf("Найденное значение d: %s\n", dRecovered.String())
		fmt.Printf("Значение функции Эйлера φ(N): %s\n", phi.String())

		fmt.Println("Вычисленные подходящие дроби (k/d):")
		for _, conv := range convergents {
			fmt.Printf("k = %s, d = %s\n", conv.K.String(), conv.D.String())
		}

		if dRecovered.Cmp(rsaService.PrivateKey.D) == 0 {
			fmt.Println("Найденное значение d совпадает с оригинальным!")
		} else {
			fmt.Println("Найденное значение d не совпадает с оригинальным.")
		}

		message := big.NewInt(123456789)
		ciphertext, err := rsaService.Encrypt(message)
		if err != nil {
			fmt.Printf("Ошибка при шифровании: %v\n", err)
			return
		}

		decryptedMessage := new(big.Int).Exp(ciphertext, dRecovered, rsaService.PublicKey.N)
		fmt.Printf("Дешифрованное сообщение с найденным d: %s\n", decryptedMessage.String())

		if message.Cmp(decryptedMessage) == 0 {
			fmt.Println("Успешно расшифровано с найденным d.")
		} else {
			fmt.Println("Не удалось расшифровать с найденным d.")
		}
	}
}
