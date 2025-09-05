package faroe

import (
	crand "crypto/rand"
	"math/rand/v2"
	"sync"
)

var uppercaseAlphabet = [32]rune{'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '2', '3', '4', '5', '6', '7', '8', '9'}

// Generates a short code with 40 bits of entropy.
// Rate limiting must be implemented to prevent brute force attacks.
func generateVerificationCode() string {
	bytes := make([]byte, 8)
	_, _ = crand.Read(bytes)
	chars := [8]rune{}
	for i := range bytes {
		// Remove 3 bits to get a random 5 bit integer
		chars[i] = uppercaseAlphabet[bytes[i]>>3]
	}
	return string(chars[:])
}

// Generates a short code with 60 bits of entropy.
// Rate limiting must be implemented to prevent brute force attacks.
func generateTemporaryPassword() string {
	bytes := make([]byte, 12)
	_, _ = crand.Read(bytes)
	chars := [12]rune{}
	for i := range bytes {
		// Remove 3 bits to get a random 5 bit integer
		chars[i] = uppercaseAlphabet[bytes[i]>>3]
	}
	return string(chars[:])
}

var lowercaseAlphabet = [32]rune{'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm', 'n', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '2', '3', '4', '5', '6', '7', '8', '9'}

func generateSecret() string {
	bytes := make([]byte, 24)
	crand.Read(bytes)
	chars := [24]rune{}
	for i := range bytes {
		// Remove 3 bits to get a random 5 bit integer
		chars[i] = lowercaseAlphabet[bytes[i]>>3]
	}
	return string(chars[:])
}

type safeChaCha8Struct struct {
	m       *sync.Mutex
	chacha8 *rand.ChaCha8
}

func (safeChaCha8 *safeChaCha8Struct) read(b []byte) {
	safeChaCha8.m.Lock()
	safeChaCha8.chacha8.Read(b)
	safeChaCha8.m.Unlock()
}

func newSafeChaCha8() *safeChaCha8Struct {
	seed := [32]byte{}
	crand.Read(seed[:])
	return &safeChaCha8Struct{m: &sync.Mutex{}, chacha8: rand.NewChaCha8(seed)}
}

var globalSafeChaCha8 = newSafeChaCha8()

func generateRandomId() string {
	bytes := make([]byte, 24)
	globalSafeChaCha8.read(bytes)
	chars := [24]rune{}
	for i := range bytes {
		// Remove 3 bits to get a random 5 bit integer
		chars[i] = lowercaseAlphabet[bytes[i]>>3]
	}
	return string(chars[:])
}
