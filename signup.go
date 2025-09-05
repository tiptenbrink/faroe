package faroe

import (
	"errors"
	"fmt"
	"time"
)

var signupExpiration = 20 * time.Minute

type signupStruct struct {
	id                           string
	secretHash                   []byte
	emailAddress                 string
	emailAddressVerificationCode string
	emailAddressVerified         bool
	passwordHash                 []byte
	passwordHashAlgorithmId      string
	passwordSalt                 []byte
	passwordSet                  bool
	createdAt                    time.Time
}

func (server *ServerStruct) verifySignupExpiration(signup signupStruct) bool {
	now := server.clock.Now()
	return now.Sub(signup.createdAt) < signupExpiration
}

func (server *ServerStruct) createSignup(emailAddress string) (signupStruct, string, error) {
	id := generateRandomId()
	secret := generateSecret()
	secretHash := createCredentialSecretHash(secret)
	userEmailAddressVerificationCode := generateVerificationCode()

	now := server.clock.Now()
	signup := signupStruct{
		id:                           id,
		secretHash:                   secretHash,
		emailAddress:                 emailAddress,
		emailAddressVerificationCode: userEmailAddressVerificationCode,
		emailAddressVerified:         false,
		passwordHash:                 nil,
		passwordHashAlgorithmId:      "",
		passwordSalt:                 nil,
		passwordSet:                  false,
		createdAt:                    now,
	}
	token := createCredentialToken(id, secret)

	err := server.setSignupInMainStorage(signup)
	if err != nil {
		return signupStruct{}, "", fmt.Errorf("failed to set signup in main storage: %s", err.Error())
	}

	return signup, token, nil
}

func (server *ServerStruct) validateSignupToken(signupToken string) (signupStruct, error) {
	signupId, signupSecret, err := parseCredentialToken(signupToken)
	if err != nil {
		return signupStruct{}, errInvalidSignupToken
	}

	signup, err := server.getValidSignup(signupId)
	if err != nil && errors.Is(err, errSignupNotFound) {
		return signupStruct{}, errInvalidSignupToken
	}
	if err != nil {
		return signupStruct{}, fmt.Errorf("failed to get valid signup: %s", err.Error())
	}
	secretValid := verifyCredentialSecret(signup.secretHash, signupSecret)
	if !secretValid {
		return signupStruct{}, errInvalidSignupToken
	}
	return signup, nil
}

func (server *ServerStruct) getValidSignup(signupId string) (signupStruct, error) {
	signup, _, err := server.getSignupFromMainStorage(signupId)
	if err != nil && errors.Is(err, errSignupNotFound) {
		return signupStruct{}, errSignupNotFound
	}
	if err != nil {
		return signupStruct{}, fmt.Errorf("failed to get signup from main storage: %s", err.Error())
	}

	expirationValid := server.verifySignupExpiration(signup)
	if !expirationValid {
		err = server.deleteSignupFromMainStorage(signup.id)
		if err != nil && !errors.Is(err, errSignupNotFound) {
			return signupStruct{}, fmt.Errorf("failed to delete signup from main storage: %s", err.Error())
		}
		return signupStruct{}, errSignupNotFound
	}

	return signup, nil
}

func (server *ServerStruct) deleteSignup(signupId string) error {
	err := server.deleteSignupFromMainStorage(signupId)
	if err != nil && errors.Is(err, errSignupNotFound) {
		return errSignupNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to delete signup from main storage: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) setSignupAsEmailAddressVerified(signupId string) error {
	signup, counter, err := server.getSignupFromMainStorage(signupId)
	if err != nil && errors.Is(err, errSignupNotFound) {
		return errConflict
	}
	if err != nil {
		return fmt.Errorf("failed to get signup from main storage: %s", err.Error())
	}

	if signup.emailAddressVerified {
		return errConflict
	}

	signup.emailAddressVerified = true

	err = server.updateSignupInMainStorage(signup, counter)
	if err != nil && errors.Is(err, errSigninNotFound) {
		return errConflict
	}
	if err != nil {
		return fmt.Errorf("failed to update signup in main storage: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) setSignupPasswordHash(signupId string, password string) error {
	passwordHash, passwordHashAlgorithmId, passwordSalt, err := server.hashUserPassword(password)
	if err != nil {
		return fmt.Errorf("failed to hash password: %s", err.Error())
	}

	signup, counter, err := server.getSignupFromMainStorage(signupId)
	if err != nil && errors.Is(err, errSigninNotFound) {
		return errConflict
	}
	if err != nil {
		return fmt.Errorf("failed to get signup from main storage: %s", err.Error())
	}

	if signup.passwordSet {
		return errConflict
	}

	signup.passwordHash = passwordHash
	signup.passwordHashAlgorithmId = passwordHashAlgorithmId
	signup.passwordSalt = passwordSalt
	signup.passwordSet = true

	err = server.updateSignupInMainStorage(signup, counter)
	if err != nil && errors.Is(err, errSigninNotFound) {
		return errConflict
	}
	if err != nil {
		return fmt.Errorf("failed to update signup in main storage: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) setSignupInMainStorage(signup signupStruct) error {
	encoded := encodeSignupToBytes(signup)
	expiresAt := signup.createdAt.Add(signupExpiration)

	err := server.mainStorage.Set(mainStorageKeyPrefixSignup+signup.id, encoded, expiresAt)
	if err != nil {
		return fmt.Errorf("failed to set entry in main storage: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) getSignupFromMainStorage(signupId string) (signupStruct, int32, error) {
	encoded, counter, err := server.mainStorage.Get(mainStorageKeyPrefixSignup + signupId)
	if err != nil && errors.Is(err, ErrMainStorageEntryNotFound) {
		return signupStruct{}, 0, errSignupNotFound
	}
	if err != nil {
		return signupStruct{}, 0, fmt.Errorf("failed to get entry from main storage: %s", err.Error())
	}

	decoded, err := decodeSignupFromBytes(encoded)
	if err != nil {
		return signupStruct{}, 0, fmt.Errorf("failed to decode signup from bytes: %s", err.Error())
	}

	return decoded, counter, nil
}

func (server *ServerStruct) deleteSignupFromMainStorage(signupId string) error {
	err := server.mainStorage.Delete(mainStorageKeyPrefixSignup + signupId)
	if err != nil && errors.Is(err, ErrMainStorageEntryNotFound) {
		return errSignupNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to delete entry from main storage: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) updateSignupInMainStorage(signup signupStruct, storageEntryCounter int32) error {
	encoded := encodeSignupToBytes(signup)
	expiresAt := signup.createdAt.Add(signupExpiration)

	err := server.mainStorage.Update(mainStorageKeyPrefixSignup+signup.id, encoded, expiresAt, storageEntryCounter)
	if err != nil && errors.Is(err, ErrMainStorageEntryNotFound) {
		return errSignupNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to update entry in main storage: %s", err.Error())
	}

	return nil
}

func encodeSignupToBytes(signup signupStruct) []byte {
	binarySequence := binarySequenceType{}
	binarySequence.addString(signup.id)
	binarySequence.add(signup.secretHash)
	binarySequence.addString(signup.emailAddress)
	binarySequence.addString(signup.emailAddressVerificationCode)
	binarySequence.addBool(signup.emailAddressVerified)
	binarySequence.add(signup.passwordHash)
	binarySequence.addString(signup.passwordHashAlgorithmId)
	binarySequence.add(signup.passwordSalt)
	binarySequence.addBool(signup.passwordSet)
	binarySequence.addInt64(signup.createdAt.Unix())
	return binarySequence.encode()
}

func decodeSignupFromBytes(encoded []byte) (signupStruct, error) {
	binarySequence, err := parseBinarySequenceBytes(encoded)
	if err != nil {
		return signupStruct{}, fmt.Errorf("failed to parse binary sequence: %s", err.Error())
	}

	signup, err := mapBinarySequenceToSignup(binarySequence)
	if err != nil {
		return signupStruct{}, fmt.Errorf("failed to map binary sequence to signup: %s", err.Error())
	}

	return signup, nil
}

func mapBinarySequenceToSignup(binarySequence binarySequenceType) (signupStruct, error) {
	id, err := binarySequence.getString(0)
	if err != nil {
		return signupStruct{}, fmt.Errorf("failed to get id: %s", err.Error())
	}
	secretHash, err := binarySequence.get(1)
	if err != nil {
		return signupStruct{}, fmt.Errorf("failed to get secret hash: %s", err.Error())
	}
	emailAddress, err := binarySequence.getString(2)
	if err != nil {
		return signupStruct{}, fmt.Errorf("failed to get email address: %s", err.Error())
	}
	emailAddressVerificationCode, err := binarySequence.getString(3)
	if err != nil {
		return signupStruct{}, fmt.Errorf("failed to get email address verification code: %s", err.Error())
	}
	emailAddressVerified, err := binarySequence.getBool(4)
	if err != nil {
		return signupStruct{}, fmt.Errorf("failed to get email address verified flag: %s", err.Error())
	}
	passwordHash, err := binarySequence.get(5)
	if err != nil {
		return signupStruct{}, fmt.Errorf("failed to get password hash: %s", err.Error())
	}
	passwordHashAlgorithmId, err := binarySequence.getString(6)
	if err != nil {
		return signupStruct{}, fmt.Errorf("failed to get password hash algorithm id: %s", err.Error())
	}
	passwordSalt, err := binarySequence.get(7)
	if err != nil {
		return signupStruct{}, fmt.Errorf("failed to get password salt: %s", err.Error())
	}
	passwordSet, err := binarySequence.getBool(8)
	if err != nil {
		return signupStruct{}, fmt.Errorf("failed to get password set flag: %s", err.Error())
	}
	createdAtUnix, err := binarySequence.getInt64(9)
	if err != nil {
		return signupStruct{}, fmt.Errorf("failed to get created at unix: %s", err.Error())
	}

	signup := signupStruct{
		id:                           id,
		secretHash:                   secretHash,
		emailAddress:                 emailAddress,
		emailAddressVerificationCode: emailAddressVerificationCode,
		emailAddressVerified:         emailAddressVerified,
		passwordHash:                 passwordHash,
		passwordHashAlgorithmId:      passwordHashAlgorithmId,
		passwordSalt:                 passwordSalt,
		passwordSet:                  passwordSet,
		createdAt:                    time.Unix(createdAtUnix, 0),
	}

	return signup, nil
}
