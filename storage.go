package faroe

import (
	"errors"
	"time"
)

const (
	mainStorageKeyPrefixSession                = "aaaa."
	mainStorageKeyPrefixSignup                 = "aaab."
	mainStorageKeyPrefixSignin                 = "aaac."
	mainStorageKeyPrefixUserEmailAddressUpdate = "aaad."
	mainStorageKeyPrefixUserPasswordUpdate     = "aaae."
	mainStorageKeyPrefixUserPasswordReset      = "aaaf."
	mainStorageKeyPrefixUserDeletion           = "aaag."
)

const (
	cacheKeyPrefixSession = "aaaa."
)

const (
	rateLimitStorageKeyPrefixVerifyUserPasswordRateLimit                             = "aaaa."
	rateLimitStorageKeyPrefixSendEmailRateLimit                                      = "aaab."
	rateLimitStorageKeyPrefixVerifyEmailAddressVerificationCodeEmailAddressRateLimit = "aaac."
	rateLimitStorageKeyPrefixVerifyUserPasswordResetTemporaryPasswordUserRateLimit   = "aaad."
)

// Keys have a maximum length of 128 bytes.
type MainStorageInterface interface {
	// Retrieves the value and counter associated with the given key, even those past expiration.
	// Returns [ErrMainStorageEntryNotFound] if the key doesn't exist.
	// An error is returned for any other failure.
	Get(key string) ([]byte, int32, error)

	// Stores the value under the given key, overwriting any existing value.
	// The counter is set to 0.
	// expiresAt is just a soft expiration hint.
	// Entries past their expiration may be deleted but it is not required.
	Set(key string, value []byte, expiresAt time.Time) error

	// Updates the value and TTL for the given key if the counter matches.
	// expiresAt is just a soft expiration hint.
	// Entries past their expiration may be deleted but it is not required.
	// Returns [ErrMainStorageEntryNotFound] if the key doesn't exist or the counter doesn't match.
	// An error is returned for any other failure.
	Update(key string, value []byte, expiresAt time.Time, counter int32) error

	// Removes the value associated with the given key.
	// Returns [ErrMainStorageEntryNotFound] if the key doesn't exist.
	// An error is returned for any other failure.
	Delete(key string) error
}

var ErrMainStorageEntryNotFound = errors.New("entry not found in main storage")

// Keys have a maximum length of 128 bytes.
type RateLimitStorageInterface interface {
	// Retrieves the value, ID, counter associated with the given key.
	// It may return entires past its expiration hint.
	// Returns [ErrMainStorageEntryNotFound] if the key doesn't exist.
	// An error is returned for any other failure.
	Get(key string) ([]byte, string, int32, error)

	// Stores a value and ID under the given key.
	// The counter is set to 0.
	// expiresAt is just a soft expiration hint.
	// Entries past their expiration may be deleted but it is not required.
	// Returns [ErrRateLimitStorageEntryAlreadyExists] if the key already exists.
	// An error is returned for any other failure.
	Add(key string, value []byte, entryId string, expiresAt time.Time) error

	// Updates the value and TTL for the given key if the ID and counter matches.
	// expiresAt is just a soft expiration hint.
	// Entries past their expiration may be deleted but it is not required.
	// Returns [ErrRateLimitStorageEntryNotFound] if the key doesn't exist, the ID doesn't match, or the counter doesn't match.
	// An error is returned for any other failure.
	Update(key string, value []byte, expiresAt time.Time, entryId string, counter int32) error

	// Removes the value associated with the given key.
	// Returns [ErrRateLimitStorageEntryNotFound] if the key doesn't exist, the ID doesn't match, or the counter doesn't match.
	// An error is returned for any other failure.
	Delete(key string, entryId string, counter int32) error
}

var ErrRateLimitStorageEntryNotFound = errors.New("entry not found in rate limit storage")
var ErrRateLimitStorageEntryAlreadyExists = errors.New("entry already exists in rate limit storage")

// Keys have a maximum length of 128 bytes.
type CacheInterface interface {
	// Retrieves the value and counter associated with the given key.
	// It should not return entries past its expiration.
	// Returns [ErrCacheEntryNotFound] if the key doesn't exist.
	// An error is returned for any other failure.
	Get(key string) ([]byte, error)

	// Stores the value under the given key, overwriting any existing value.
	// The initial entry counter is set to 0.
	Set(key string, value []byte, ttl time.Duration) error

	// Removes the value associated with the given key.
	Delete(key string) error
}

var ErrCacheEntryNotFound = errors.New("entry not found in cache")

// Implements [CacheInterface].
// Stores nothing.
var EmptyCache = emptyCacheStruct{}

type emptyCacheStruct struct{}

func (emptyCacheStruct) Get(_ string) ([]byte, error) {
	return nil, ErrCacheEntryNotFound
}

func (emptyCacheStruct) Set(_ string, _ []byte, _ time.Time) error {
	return nil
}

func (emptyCacheStruct) Delete(_ string) error {
	return nil
}
