package faroe

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
)

func (server *ServerStruct) hashPassword(algorithm PasswordHashAlgorithmInterface, secret string) ([]byte, []byte, error) {
	salt := make([]byte, algorithm.SaltSize())
	_, _ = rand.Read(salt)

	server.passwordHashingSemaphore.Acquire(context.Background(), 1)
	hash, err := algorithm.Hash(secret, salt)
	server.passwordHashingSemaphore.Release(1)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to hash secret with %s: %s", algorithm.Id(), err.Error())
	}

	return hash, salt, nil
}

func (server *ServerStruct) verifyPasswordAgainstHash(algorithm PasswordHashAlgorithmInterface, password string, hash []byte, salt []byte) (bool, error) {
	server.passwordHashingSemaphore.Acquire(context.Background(), 1)
	hashed, err := algorithm.Hash(password, salt)
	server.passwordHashingSemaphore.Release(1)
	if err != nil {
		return false, fmt.Errorf("failed to hash secret with %s: %s", algorithm.Id(), err.Error())
	}
	equaled := subtle.ConstantTimeCompare(hashed, hash) == 1
	return equaled, nil
}

func (server *ServerStruct) hashUserPassword(userPassword string) ([]byte, string, []byte, error) {
	algorithm := server.userPasswordHashAlgorithms[0]
	hash, salt, err := server.hashPassword(algorithm, userPassword)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to hash user password: %s", err.Error())
	}
	return hash, algorithm.Id(), salt, nil
}

func (server *ServerStruct) verifyUserPassword(password string, passwordHash []byte, hashAlgorithmId string, passwordSalt []byte) (bool, error) {
	for _, algorithm := range server.userPasswordHashAlgorithms {
		if algorithm.Id() == hashAlgorithmId {
			valid, err := server.verifyPasswordAgainstHash(algorithm, password, passwordHash, passwordSalt)
			if err != nil {
				return false, fmt.Errorf("failed to verify user password against hash: %s", err.Error())
			}
			return valid, nil
		}
	}
	return false, errHashAlgorithmNotSupported
}

func (server *ServerStruct) hashTemporaryPassword(temporaryPassword string) ([]byte, string, []byte, error) {
	hash, salt, err := server.hashPassword(server.temporaryPasswordHashAlgorithm, temporaryPassword)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to hash user password with %s: %s", server.temporaryPasswordHashAlgorithm.Id(), err.Error())
	}
	return hash, server.temporaryPasswordHashAlgorithm.Id(), salt, nil
}

func (server *ServerStruct) verifyTemporaryPassword(temporaryPassword string, temporaryPasswordHash []byte, hashAlgorithmId string, temporaryPasswordSalt []byte) (bool, error) {
	if server.temporaryPasswordHashAlgorithm.Id() != hashAlgorithmId {
		return false, errHashAlgorithmNotSupported
	}
	valid, err := server.verifyPasswordAgainstHash(server.temporaryPasswordHashAlgorithm, temporaryPassword, temporaryPasswordHash, temporaryPasswordSalt)
	if err != nil {
		return false, fmt.Errorf("failed to verify temporary password against hash: %s", err.Error())
	}
	return valid, nil
}

var errHashAlgorithmNotSupported = errors.New("hash algorithm not supported")

type PasswordHashAlgorithmInterface interface {
	// A unique identifier of this algorithm.
	Id() string

	SaltSize() int

	Hash(password string, salt []byte) ([]byte, error)
}
