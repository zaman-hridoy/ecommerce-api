package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func main() {

	const tokenSize = 32

 	generateToken :=  func() (string, error) {
		bytes := make([]byte, tokenSize)

		if _, err := rand.Read(bytes); err != nil {
			return "", fmt.Errorf("generate token: %w", err)
		}

		return base64.RawStdEncoding.EncodeToString(bytes), nil
	}
	token, _ := generateToken()
	fmt.Println(token)

	hash := sha256.Sum256([]byte(token))

	hashed := hex.EncodeToString(hash[:])
	fmt.Println(hashed)


	// password := "Hello1234"

	// hash := sha256.Sum256([]byte(password))
	// // h := sha256.New()

	// fmt.Printf("%x", hash)

	// passwordHash1, _ := auth.HashPassword(password)
	// passwordHash2, _ := auth.HashPassword(password)
	// fmt.Println(passwordHash1)
	// fmt.Println(passwordHash2)
	// isVerified, _ := auth.CheckPassword(password, passwordHash1)
	// fmt.Println("isVerified:", isVerified)
}

// e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
// e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855