package services

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

type EncryptionService struct {
	key []byte
}

func NewEncryptionService(keyString string) *EncryptionService {
	key := []byte(keyString)
	if len(key) < 32 {
		paddedKey := make([]byte, 32)
		copy(paddedKey, key)
		key = paddedKey
	} else if len(key) > 32 {
		key = key[:32]
	}
	
	return &EncryptionService{
		key: key,
	}
}

func (s *EncryptionService) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	plaintextBytes := []byte(plaintext)
	ciphertext := make([]byte, aes.BlockSize+len(plaintextBytes))
	
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("failed to generate IV: %w", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintextBytes)

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func (s *EncryptionService) Decrypt(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}

	ciphertextBytes, err := base64.URLEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	if len(ciphertextBytes) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}

	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	iv := ciphertextBytes[:aes.BlockSize]
	ciphertextBytes = ciphertextBytes[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertextBytes, ciphertextBytes)

	return string(ciphertextBytes), nil
}

func (s *EncryptionService) EncryptJSON(data interface{}) (string, error) {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}
	return s.Encrypt(string(jsonBytes))
}

func (s *EncryptionService) DecryptJSON(ciphertext string, target interface{}) error {
	plaintext, err := s.Decrypt(ciphertext)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(plaintext), target)
}