package faroe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"
)

type tokenBucketRateLimit struct {
	rateLimitStorage RateLimitStorageInterface
	storageKeyPrefix string
	maxTokens        uint8
	refillInterval   time.Duration
	clock            ClockInterface
}

func newTokenBucketRateLimit(rateLimitStorage RateLimitStorageInterface, storageKeyPrefix string, clock ClockInterface, maxTokens uint8, refillInterval time.Duration) *tokenBucketRateLimit {
	rl := &tokenBucketRateLimit{
		rateLimitStorage: rateLimitStorage,
		storageKeyPrefix: storageKeyPrefix,
		maxTokens:        maxTokens,
		refillInterval:   refillInterval,
		clock:            clock,
	}
	return rl
}

func (tokenBucketRateLimit *tokenBucketRateLimit) storageKey(rateLimitKey string) string {
	return tokenBucketRateLimit.storageKeyPrefix + rateLimitKey
}

func (tokenBucketRateLimit *tokenBucketRateLimit) checkTokens(key string) (bool, error) {
	now := tokenBucketRateLimit.clock.Now()

	tokenBucket, _, _, err := tokenBucketRateLimit.getTokenBucketFromStorage(key)
	if err != nil && errors.Is(err, errTokenBucketNotFound) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to get token bucket from storage: %s", err.Error())
	}
	refill := uint8(now.Sub(tokenBucket.lastRefilledAt) / tokenBucketRateLimit.refillInterval)
	if tokenBucket.count+refill < tokenBucketRateLimit.maxTokens {
		tokenBucket.count += refill
	} else {
		tokenBucket.count = tokenBucketRateLimit.maxTokens
	}
	return tokenBucket.count > 0, nil
}

func (tokenBucketRateLimit *tokenBucketRateLimit) consumeToken(key string) (bool, error) {
	now := tokenBucketRateLimit.clock.Now()

	tokenBucket, storageEntryId, storageEntryCounter, err := tokenBucketRateLimit.getTokenBucketFromStorage(key)
	if err != nil && errors.Is(err, errTokenBucketNotFound) {
		tokenBucket := tokenBucketStruct{tokenBucketRateLimit.maxTokens - 1, now}

		err = tokenBucketRateLimit.addTokenBucketToStorage(key, tokenBucket)
		if err != nil && errors.Is(err, errTokenBucketAlreadyExists) {
			return false, errTokenBucketRateLimitInternalConflict
		}
		if err != nil {
			return false, fmt.Errorf("failed to add token bucket to storage: %s", err.Error())
		}
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to get token bucket from storage: %s", err.Error())
	}
	if storageEntryCounter == math.MaxInt32 {
		err = tokenBucketRateLimit.deleteTokenBucketFromStorage(key, storageEntryId, storageEntryCounter)
		if err != nil && errors.Is(err, errTokenBucketAlreadyExists) {
			return false, errTokenBucketRateLimitInternalConflict
		}
		if err != nil {
			return false, fmt.Errorf("failed to delete token bucket from storage: %s", err.Error())
		}

		tokenBucket := tokenBucketStruct{tokenBucketRateLimit.maxTokens - 1, now}

		err = tokenBucketRateLimit.addTokenBucketToStorage(key, tokenBucket)
		if err != nil && errors.Is(err, errTokenBucketAlreadyExists) {
			return false, errTokenBucketRateLimitInternalConflict
		}
		if err != nil {
			return false, fmt.Errorf("failed to add token bucket to storage: %s", err.Error())
		}
		return true, nil
	}

	refill := uint8(now.Sub(tokenBucket.lastRefilledAt) / tokenBucketRateLimit.refillInterval)
	if tokenBucket.count+refill < tokenBucketRateLimit.maxTokens {
		tokenBucket.count += refill
		tokenBucket.lastRefilledAt = tokenBucket.lastRefilledAt.Add(tokenBucketRateLimit.refillInterval * time.Duration(refill))
	} else {
		tokenBucket.count = tokenBucketRateLimit.maxTokens
		tokenBucket.lastRefilledAt = tokenBucket.lastRefilledAt.Add(tokenBucketRateLimit.refillInterval * time.Duration(tokenBucketRateLimit.maxTokens))
	}

	if tokenBucket.count < 1 {
		return false, nil
	}

	tokenBucket.count--

	err = tokenBucketRateLimit.updateTokenBucketInStorage(key, tokenBucket, storageEntryId, storageEntryCounter)
	if err != nil && errors.Is(err, errTokenBucketNotFound) {
		return false, errTokenBucketRateLimitInternalConflict
	}
	if err != nil {
		return false, fmt.Errorf("failed to update token bucket in storage: %s", err.Error())
	}

	return true, nil
}

func (tokenBucketRateLimit *tokenBucketRateLimit) getTokenBucketFromStorage(rateLimitKey string) (tokenBucketStruct, string, int32, error) {
	storageKey := tokenBucketRateLimit.storageKey(rateLimitKey)

	encoded, entryId, counter, err := tokenBucketRateLimit.rateLimitStorage.Get(storageKey)
	if err != nil && errors.Is(err, ErrRateLimitStorageEntryNotFound) {
		return tokenBucketStruct{}, "", 0, errTokenBucketNotFound
	}
	if err != nil {
		return tokenBucketStruct{}, "", 0, fmt.Errorf("failed to get entry from rate limit storage: %s", err.Error())
	}

	decoded, err := decodeTokenBucketFromBytes(encoded)
	if err != nil {
		return tokenBucketStruct{}, "", 0, fmt.Errorf("failed to decode token bucket from bytes: %s", err.Error())
	}

	return decoded, entryId, counter, nil
}

func (tokenBucketRateLimit *tokenBucketRateLimit) addTokenBucketToStorage(rateLimitKey string, tokenBucket tokenBucketStruct) error {
	storageKey := tokenBucketRateLimit.storageKey(rateLimitKey)
	entryId := generateRandomId()
	encoded := encodeTokenBucketToBytes(tokenBucket)
	expiresAt := tokenBucket.lastRefilledAt.Add(time.Duration(tokenBucketRateLimit.maxTokens-tokenBucket.count) * tokenBucketRateLimit.refillInterval)

	err := tokenBucketRateLimit.rateLimitStorage.Add(storageKey, encoded, entryId, expiresAt)
	if err != nil && errors.Is(err, ErrRateLimitStorageEntryAlreadyExists) {
		return errTokenBucketAlreadyExists
	}
	if err != nil {
		return fmt.Errorf("failed to add entry to rate limit storage: %s", err.Error())
	}

	return nil
}

func (tokenBucketRateLimit *tokenBucketRateLimit) updateTokenBucketInStorage(rateLimitKey string, tokenBucket tokenBucketStruct, storageEntryId string, storageEntryCounter int32) error {
	storageKey := tokenBucketRateLimit.storageKey(rateLimitKey)
	encoded := encodeTokenBucketToBytes(tokenBucket)
	expiresAt := tokenBucket.lastRefilledAt.Add(time.Duration(tokenBucketRateLimit.maxTokens-tokenBucket.count) * tokenBucketRateLimit.refillInterval)

	err := tokenBucketRateLimit.rateLimitStorage.Update(storageKey, encoded, expiresAt, storageEntryId, storageEntryCounter)
	if err != nil && errors.Is(err, ErrRateLimitStorageEntryNotFound) {
		return errTokenBucketNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to update entry in rate limit storage: %s", err.Error())
	}

	return nil
}

func (tokenBucketRateLimit *tokenBucketRateLimit) deleteTokenBucketFromStorage(rateLimitKey string, storageEntryId string, storageEntryCounter int32) error {
	storageKey := tokenBucketRateLimit.storageKey(rateLimitKey)

	err := tokenBucketRateLimit.rateLimitStorage.Delete(storageKey, storageEntryId, storageEntryCounter)
	if err != nil && errors.Is(err, ErrRateLimitStorageEntryNotFound) {
		return errTokenBucketNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to delete entry from rate limit storage: %s", err.Error())
	}

	return nil
}

type tokenBucketStruct struct {
	count          uint8
	lastRefilledAt time.Time
}

func encodeTokenBucketToBytes(tokenBucket tokenBucketStruct) []byte {
	encoded := [9]byte{}
	encoded[0] = tokenBucket.count
	binary.BigEndian.PutUint64(encoded[1:], uint64(tokenBucket.lastRefilledAt.Unix()))
	return encoded[:]
}

func decodeTokenBucketFromBytes(binaryTokenBucket []byte) (tokenBucketStruct, error) {
	if len(binaryTokenBucket) != 9 {
		return tokenBucketStruct{}, fmt.Errorf("invalid encoding")
	}
	count := uint8(binaryTokenBucket[0])
	lastRefilledAtUnixUint64 := binary.BigEndian.Uint64(binaryTokenBucket[1:])
	lastRefilledAt := time.Unix(int64(lastRefilledAtUnixUint64), 0)
	decoded := tokenBucketStruct{count, lastRefilledAt}
	return decoded, nil
}

var errTokenBucketNotFound = errors.New("token bucket not found")
var errTokenBucketAlreadyExists = errors.New("token bucket already exists")
var errTokenBucketRateLimitInternalConflict = errors.New("internal conflict")
