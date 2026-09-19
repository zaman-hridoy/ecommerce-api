package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)



type passwordParams struct {
	memory			uint32
	iterations		uint32
	parallellism	uint8
	saltLength		uint32
	keyLength		uint32
}

var defaultPassowrdParams = passwordParams{
	memory: 19 * 1024, // in kib
	iterations: 2,
	parallellism: 1,
	saltLength: 16, // in bytes -> 16 * 8 = 128bit
	keyLength: 32, // 32 * 8 = 256 bits
}

func generateRandomBytes(length uint32) ([]byte, error) {
	bytes := make([]byte, length)

	if _, err := rand.Read(bytes); err != nil {
		return nil, fmt.Errorf("generate random bytes: %w", err)
	}
	return bytes, nil
}

func encodePasswordHash(
	hash []byte,
	salt []byte,
	params passwordParams,
) string {
	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedHash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		params.memory,
		params.iterations,
		params.parallellism,
		encodedSalt,
		encodedHash,
	)
}

func HashPassword(password string) (string, error) {
	params := defaultPassowrdParams

	salt, err := generateRandomBytes(params.saltLength)
	if err != nil {
		return "", err
	}

	hash := argon2.IDKey(
		[]byte(password), 
		salt, 
		params.iterations, 
		params.memory, 
		params.parallellism,
		params.keyLength,
	)

	return encodePasswordHash(hash, salt, params), nil
}

func CheckPassword(password string, encodedHash string) (bool, error) {
	params, salt, expectedHash, err := decodePasswordHash(encodedHash)
	
	if err != nil {
		return false, err
	}

	actualHash := argon2.IDKey(
		[]byte(password),
		salt,
		params.iterations,
		params.memory,
		params.parallellism,
		params.keyLength,
	)

	return subtle.ConstantTimeCompare(actualHash, expectedHash) == 1, nil
}

func decodePasswordHash(encodedHash string) (
	passwordParams,
	[]byte,
	[]byte,
	error,
) {
	// $argon2id$v=19$m=19456,t=2,p=1$A/n6LCUqY/MdHozpFanKrg$/YmmQ4b6i91K2N98Ps6cldjTuVv1TnyDxv36WdawwcY

	parts := strings.Split(encodedHash, "$")

	
	if len(parts) != 6 {
		return passwordParams{}, nil, nil, fmt.Errorf("invalid password hash format")
	}

	if parts[1] != "argon2id" {
		return passwordParams{}, nil, nil, fmt.Errorf("invalid password hash algorithm")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return passwordParams{}, nil, nil, fmt.Errorf("pasrse argon2 version: %w", err)
	}

	if version != argon2.Version {
		return passwordParams{}, nil, nil, fmt.Errorf("unsupported argon2 version")
	}

	var params passwordParams

	if _, err:= fmt.Sscanf(
		parts[3], 
		"m=%d,t=%d,p=%d", 
		&params.memory, 
		&params.iterations,
		&params.parallellism,
	); err != nil {
		return passwordParams{}, nil, nil, fmt.Errorf("parse argon2 parameters: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return passwordParams{}, nil, nil, fmt.Errorf("decode password salt: %w", err)
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return passwordParams{}, nil, nil, fmt.Errorf("decode password hash: %w", err)
	}

	params.saltLength = uint32(len(salt))
	params.keyLength = uint32(len(hash))
	return params, salt, hash, nil
}