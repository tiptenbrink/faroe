package faroe

import (
	"time"

	"golang.org/x/sync/semaphore"
)

// Use [NewServer].
type ServerStruct struct {
	mainStorage MainStorageInterface
	cache       CacheInterface

	errorLogger                        ActionErrorLoggerInterface
	userPasswordHashAlgorithms         []PasswordHashAlgorithmInterface
	temporaryPasswordHashAlgorithm     PasswordHashAlgorithmInterface
	passwordHashingSemaphore           *semaphore.Weighted
	clock                              ClockInterface
	userServerInvocationEndpointClient ActionInvocationEndpointClientInterface
	newEmailAddressChecker             EmailAddressCheckerInterface
	emailSender                        EmailSenderInterface
	sessionConfig                      SessionConfigStruct

	verifyUserPasswordRateLimit                             *tokenBucketRateLimit
	sendEmailRateLimit                                      *tokenBucketRateLimit
	verifyEmailAddressVerificationCodeEmailAddressRateLimit *tokenBucketRateLimit
	verifyUserPasswordResetTemporaryPasswordUserRateLimit   *tokenBucketRateLimit
}

// All interfaces must be defined and cannot be nil.
//
// Storage entry keys are not globally-scoped. Different entries in mainStorage, cache, and rateLimitStorage may share the same key.
//
// maxConcurrentPasswordHashingProcesses defines the maximum number of concurrent processes for user password and temporary password hashing.
//
// emailAddressChecker is used for checking email addresses for signup and new email addresses of user email address updates.
// It is not used in for sign ins or user password resets.
//
// InactivityTimeout and ActivityCheckInterval should be a non-zero value in sessionConfig.
func NewServer(
	mainStorage MainStorageInterface,
	cache CacheInterface,
	rateLimitStorage RateLimitStorageInterface,
	errorLogger ActionErrorLoggerInterface,
	userPasswordHashAlgorithms []PasswordHashAlgorithmInterface,
	temporaryPasswordHashAlgorithm PasswordHashAlgorithmInterface,
	maxConcurrentPasswordHashingProcesses int,
	clock ClockInterface,
	newEmailAddressChecker EmailAddressCheckerInterface,
	emailSender EmailSenderInterface,
	userServerActionInvocationEndpointClient ActionInvocationEndpointClientInterface,
	sessionConfig SessionConfigStruct,
) *ServerStruct {
	verifyUserPasswordRateLimit := newTokenBucketRateLimit(rateLimitStorage, rateLimitStorageKeyPrefixVerifyUserPasswordRateLimit, clock, 5, time.Minute)
	sendEmailRateLimit := newTokenBucketRateLimit(rateLimitStorage, rateLimitStorageKeyPrefixSendEmailRateLimit, clock, 5, 30*time.Minute)
	verifyEmailAddressVerificationCodeEmailAddressRateLimit := newTokenBucketRateLimit(rateLimitStorage, rateLimitStorageKeyPrefixVerifyEmailAddressVerificationCodeEmailAddressRateLimit, clock, 5, time.Minute)
	verifyUserPasswordResetTemporaryPasswordUserRateLimit := newTokenBucketRateLimit(rateLimitStorage, rateLimitStorageKeyPrefixVerifyUserPasswordResetTemporaryPasswordUserRateLimit, clock, 5, time.Minute)

	action := &ServerStruct{
		mainStorage:                        mainStorage,
		cache:                              cache,
		errorLogger:                        errorLogger,
		userPasswordHashAlgorithms:         userPasswordHashAlgorithms,
		temporaryPasswordHashAlgorithm:     temporaryPasswordHashAlgorithm,
		passwordHashingSemaphore:           semaphore.NewWeighted(int64(maxConcurrentPasswordHashingProcesses)),
		clock:                              clock,
		userServerInvocationEndpointClient: userServerActionInvocationEndpointClient,
		newEmailAddressChecker:             newEmailAddressChecker,
		emailSender:                        emailSender,
		sessionConfig:                      sessionConfig,

		verifyUserPasswordRateLimit:                             verifyUserPasswordRateLimit,
		sendEmailRateLimit:                                      sendEmailRateLimit,
		verifyEmailAddressVerificationCodeEmailAddressRateLimit: verifyEmailAddressVerificationCodeEmailAddressRateLimit,
		verifyUserPasswordResetTemporaryPasswordUserRateLimit:   verifyUserPasswordResetTemporaryPasswordUserRateLimit,
	}

	return action
}
