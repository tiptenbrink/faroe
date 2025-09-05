package faroe

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"strings"
)

func createCredentialToken(id string, secret string) string {
	return id + "." + secret
}

func createCredentialSecretHash(secret string) []byte {
	return sha256.New().Sum([]byte(secret))
}

func verifyCredentialSecret(hash []byte, secret string) bool {
	secretHash := createCredentialSecretHash(secret)
	return subtle.ConstantTimeCompare(hash, secretHash) == 1
}

func parseCredentialToken(token string) (string, string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return "", "", errors.New("invalid token")
	}
	return parts[0], parts[1], nil
}
