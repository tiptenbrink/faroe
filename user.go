package faroe

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/faroedev/go-json"
)

const (
	userServerActionCreateUser                   = "create_user"
	userServerActionGetUser                      = "get_user"
	userServerActionGetUserByEmailAddress        = "get_user_by_email_address"
	userServerActionUpdateUserEmailAddress       = "update_user_email_address"
	userServerActionUpdateUserPasswordHash       = "update_user_password_hash"
	userServerActionIncrementUserSessionsCounter = "increment_user_sessions_counter"
	userServerActionDeleteUser                   = "delete_user"
)

type userStruct struct {
	id                      string
	emailAddress            string
	passwordHash            []byte
	passwordSalt            []byte
	passwordHashAlgorithmId string
	disabled                bool
	displayName             string
	emailAddressCounter     int32
	passwordHashCounter     int32
	disabledCounter         int32
	sessionsCounter         int32
}

func (server *ServerStruct) createUser(emailAddress string, passwordHash []byte, passwordHashAlgorithmId string, passwordSalt []byte) (userStruct, error) {
	encodedPasswordHash := base64.StdEncoding.EncodeToString(passwordHash)
	encodedPasswordSalt := base64.StdEncoding.EncodeToString(passwordSalt)

	argumentsJSONBuilder := json.NewObjectBuilder()
	argumentsJSONBuilder.AddString("email_address", emailAddress)
	argumentsJSONBuilder.AddString("password_hash", encodedPasswordHash)
	argumentsJSONBuilder.AddString("password_hash_algorithm_id", passwordHashAlgorithmId)
	argumentsJSONBuilder.AddString("password_salt", encodedPasswordSalt)
	argumentsJSON := argumentsJSONBuilder.Done()

	_, valuesJSONObject, err := sendActionInvocationRequest(server.userServerInvocationEndpointClient, userServerActionCreateUser, argumentsJSON)
	if err != nil {
		if actionInvocationActionErr, ok := err.(*actionInvocationActionErrorStruct); ok {
			if actionInvocationActionErr.errorCode == "internal_error" {
				return userStruct{}, fmt.Errorf("action invocation %s failed: internal error", actionInvocationActionErr.actionInvocationId)
			}
			if actionInvocationActionErr.errorCode == "internal_conflict" {
				return userStruct{}, fmt.Errorf("action invocation %s failed: internal conflict", actionInvocationActionErr.actionInvocationId)
			}
			if actionInvocationActionErr.errorCode == "email_address_already_used" {
				return userStruct{}, errUserEmailAddressAlreadyUsed
			}
			return userStruct{}, fmt.Errorf("action invocation %s failed: unknown error code %s", actionInvocationActionErr.actionInvocationId, actionInvocationActionErr.errorCode)
		}
		return userStruct{}, fmt.Errorf("failed to send action invocation request: %s", err.Error())
	}

	userJSONObject, err := valuesJSONObject.GetJSONObject("user")
	if err != nil {
		return userStruct{}, fmt.Errorf("failed to read 'user' field from values json object: %s", err.Error())
	}

	user, err := mapJSONObjectToUser(userJSONObject)
	if err != nil {
		return userStruct{}, fmt.Errorf("failed to map json object to user: %s", err.Error())
	}

	return user, nil
}

func (server *ServerStruct) getUser(userId string) (userStruct, error) {
	argumentsJSONBuilder := json.NewObjectBuilder()
	argumentsJSONBuilder.AddString("user_id", userId)
	argumentsJSON := argumentsJSONBuilder.Done()

	_, valuesJSONObject, err := sendActionInvocationRequest(server.userServerInvocationEndpointClient, userServerActionGetUser, argumentsJSON)
	if err != nil {
		if actionInvocationActionErr, ok := err.(*actionInvocationActionErrorStruct); ok {
			if actionInvocationActionErr.errorCode == "internal_error" {
				return userStruct{}, fmt.Errorf("action invocation %s failed: internal error", actionInvocationActionErr.actionInvocationId)
			}
			if actionInvocationActionErr.errorCode == "internal_conflict" {
				return userStruct{}, fmt.Errorf("action invocation %s failed: internal conflict", actionInvocationActionErr.actionInvocationId)
			}
			if actionInvocationActionErr.errorCode == "user_not_found" {
				return userStruct{}, errUserNotFound
			}
			return userStruct{}, fmt.Errorf("action invocation %s failed: unknown error code %s", actionInvocationActionErr.actionInvocationId, actionInvocationActionErr.errorCode)
		}
		return userStruct{}, fmt.Errorf("failed to send action invocation request: %s", err.Error())
	}

	userJSONObject, err := valuesJSONObject.GetJSONObject("user")
	if err != nil {
		return userStruct{}, fmt.Errorf("failed to read 'user' field from values json object: %s", err.Error())
	}

	user, err := mapJSONObjectToUser(userJSONObject)
	if err != nil {
		return userStruct{}, fmt.Errorf("failed to map json object to user: %s", err.Error())
	}

	return user, nil
}

func (server *ServerStruct) getUserByEmailAddress(emailAddress string) (userStruct, error) {
	argumentsJSONBuilder := json.NewObjectBuilder()
	argumentsJSONBuilder.AddString("email_address", emailAddress)
	argumentsJSON := argumentsJSONBuilder.Done()

	_, valuesJSONObject, err := sendActionInvocationRequest(server.userServerInvocationEndpointClient, userServerActionGetUserByEmailAddress, argumentsJSON)
	if err != nil {
		if actionInvocationActionErr, ok := err.(*actionInvocationActionErrorStruct); ok {
			if actionInvocationActionErr.errorCode == "internal_error" {
				return userStruct{}, fmt.Errorf("action invocation %s failed: internal error", actionInvocationActionErr.actionInvocationId)
			}
			if actionInvocationActionErr.errorCode == "internal_conflict" {
				return userStruct{}, fmt.Errorf("action invocation %s failed: internal conflict", actionInvocationActionErr.actionInvocationId)
			}
			if actionInvocationActionErr.errorCode == "user_not_found" {
				return userStruct{}, errUserNotFound
			}
			return userStruct{}, fmt.Errorf("action invocation %s failed: unknown error code %s", actionInvocationActionErr.actionInvocationId, actionInvocationActionErr.errorCode)
		}
		return userStruct{}, fmt.Errorf("failed to send action invocation request: %s", err.Error())
	}

	userJSONObject, err := valuesJSONObject.GetJSONObject("user")
	if err != nil {
		return userStruct{}, fmt.Errorf("failed to read 'user' field from values json object: %s", err.Error())
	}

	user, err := mapJSONObjectToUser(userJSONObject)
	if err != nil {
		return userStruct{}, fmt.Errorf("failed to map json object to user: %s", err.Error())
	}

	return user, nil
}

func (server *ServerStruct) updateUserEmailAddress(userId string, emailAddress string, userEmailAddressCounter int32) error {
	argumentsJSONBuilder := json.NewObjectBuilder()
	argumentsJSONBuilder.AddString("user_id", userId)
	argumentsJSONBuilder.AddString("email_address", emailAddress)
	argumentsJSONBuilder.AddInt32("user_email_address_counter", userEmailAddressCounter)
	argumentsJSON := argumentsJSONBuilder.Done()

	_, _, err := sendActionInvocationRequest(server.userServerInvocationEndpointClient, userServerActionUpdateUserEmailAddress, argumentsJSON)
	if err != nil {
		if actionInvocationActionErr, ok := err.(*actionInvocationActionErrorStruct); ok {
			if actionInvocationActionErr.errorCode == "internal_error" {
				return fmt.Errorf("action invocation %s failed: internal error", actionInvocationActionErr.actionInvocationId)
			}
			if actionInvocationActionErr.errorCode == "internal_conflict" {
				return fmt.Errorf("action invocation %s failed: internal conflict", actionInvocationActionErr.actionInvocationId)
			}
			if actionInvocationActionErr.errorCode == "user_not_found" {
				return errUserNotFound
			}
			if actionInvocationActionErr.errorCode == "email_address_already_used" {
				return errUserEmailAddressAlreadyUsed
			}
			return fmt.Errorf("action invocation %s failed: unknown error code %s", actionInvocationActionErr.actionInvocationId, actionInvocationActionErr.errorCode)
		}
		return fmt.Errorf("failed to send action invocation request: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) updateUserPasswordHash(userId string, passwordHash []byte, passwordHashAlgorithmId string, passwordSalt []byte, userPasswordHashCounter int32) error {
	encodedPasswordHash := base64.StdEncoding.EncodeToString(passwordHash)
	encodedPasswordSalt := base64.StdEncoding.EncodeToString(passwordSalt)

	argumentsJSONBuilder := json.NewObjectBuilder()
	argumentsJSONBuilder.AddString("user_id", userId)
	argumentsJSONBuilder.AddString("password_hash", encodedPasswordHash)
	argumentsJSONBuilder.AddString("password_hash_algorithm_id", passwordHashAlgorithmId)
	argumentsJSONBuilder.AddString("password_salt", encodedPasswordSalt)
	argumentsJSONBuilder.AddInt32("user_password_hash_counter", userPasswordHashCounter)
	argumentsJSON := argumentsJSONBuilder.Done()

	_, _, err := sendActionInvocationRequest(server.userServerInvocationEndpointClient, userServerActionUpdateUserPasswordHash, argumentsJSON)
	if err != nil {
		if actionInvocationActionErr, ok := err.(*actionInvocationActionErrorStruct); ok {
			if actionInvocationActionErr.errorCode == "internal_error" {
				return fmt.Errorf("action invocation %s failed: internal error", actionInvocationActionErr.actionInvocationId)
			}
			if actionInvocationActionErr.errorCode == "internal_conflict" {
				return fmt.Errorf("action invocation %s failed: internal conflict", actionInvocationActionErr.actionInvocationId)
			}
			if actionInvocationActionErr.errorCode == "user_not_found" {
				return errUserNotFound
			}
			if actionInvocationActionErr.errorCode == "email_address_already_used" {
				return errUserEmailAddressAlreadyUsed
			}
			return fmt.Errorf("action invocation %s failed: unknown error code %s", actionInvocationActionErr.actionInvocationId, actionInvocationActionErr.errorCode)
		}
		return fmt.Errorf("failed to send action invocation request: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) incrementUserSessionsCounter(userId string, userSessionsCounter int32) error {
	argumentsJSONBuilder := json.NewObjectBuilder()
	argumentsJSONBuilder.AddString("user_id", userId)
	argumentsJSONBuilder.AddInt32("user_sessions_counter", userSessionsCounter)
	argumentsJSON := argumentsJSONBuilder.Done()

	_, _, err := sendActionInvocationRequest(server.userServerInvocationEndpointClient, userServerActionIncrementUserSessionsCounter, argumentsJSON)
	if err != nil {
		if actionInvocationActionErr, ok := err.(*actionInvocationActionErrorStruct); ok {
			if actionInvocationActionErr.errorCode == "internal_error" {
				return fmt.Errorf("action invocation %s failed: internal error", actionInvocationActionErr.actionInvocationId)
			}
			if actionInvocationActionErr.errorCode == "internal_conflict" {
				return fmt.Errorf("action invocation %s failed: internal conflict", actionInvocationActionErr.actionInvocationId)
			}
			if actionInvocationActionErr.errorCode == "user_not_found" {
				return errUserNotFound
			}
			if actionInvocationActionErr.errorCode == "email_address_already_used" {
				return errUserEmailAddressAlreadyUsed
			}
			return fmt.Errorf("action invocation %s failed: unknown error code %s", actionInvocationActionErr.actionInvocationId, actionInvocationActionErr.errorCode)
		}
		return fmt.Errorf("failed to send action invocation request: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) deleteUser(userId string) error {
	argumentsJSONBuilder := json.NewObjectBuilder()
	argumentsJSONBuilder.AddString("user_id", userId)
	argumentsJSON := argumentsJSONBuilder.Done()

	_, _, err := sendActionInvocationRequest(server.userServerInvocationEndpointClient, userServerActionDeleteUser, argumentsJSON)
	if err != nil {
		if actionInvocationActionErr, ok := err.(*actionInvocationActionErrorStruct); ok {
			if actionInvocationActionErr.errorCode == "internal_error" {
				return fmt.Errorf("action invocation %s failed: internal error", actionInvocationActionErr.actionInvocationId)
			}
			if actionInvocationActionErr.errorCode == "internal_conflict" {
				return fmt.Errorf("action invocation %s failed: internal conflict", actionInvocationActionErr.actionInvocationId)
			}
			if actionInvocationActionErr.errorCode == "user_not_found" {
				return errUserNotFound
			}
			return fmt.Errorf("action invocation %s failed: unknown error code %s", actionInvocationActionErr.actionInvocationId, actionInvocationActionErr.errorCode)
		}
		return fmt.Errorf("failed to send action invocation request: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) checkEmailAddressAvailability(emailAddress string) (bool, error) {
	_, err := server.getUserByEmailAddress(emailAddress)
	if err != nil && errors.Is(err, errUserNotFound) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to get user from user api: %s", err.Error())
	}
	return false, nil
}

func mapJSONObjectToUser(userJSON json.ObjectStruct) (userStruct, error) {
	userId, err := userJSON.GetString("id")
	if err != nil {
		return userStruct{}, fmt.Errorf("failed to read 'id' field: %s", err.Error())
	}
	emailAddress, err := userJSON.GetString("email_address")
	if err != nil {
		return userStruct{}, fmt.Errorf("failed to read 'email_address' field: %s", err.Error())
	}
	encodedPasswordHash, err := userJSON.GetString("password_hash")
	if err != nil {
		return userStruct{}, fmt.Errorf("failed to read 'password_hash' field: %s", err.Error())
	}
	passwordHashAlgorithmId, err := userJSON.GetString("password_hash_algorithm_id")
	if err != nil {
		return userStruct{}, fmt.Errorf("failed to read 'password_hash_algorithm_id' field: %s", err.Error())
	}
	encodedPasswordSalt, err := userJSON.GetString("password_salt")
	if err != nil {
		return userStruct{}, fmt.Errorf("failed to read 'password_salt' field: %s", err.Error())
	}
	displayName, err := userJSON.GetString("display_name")
	if err != nil {
		return userStruct{}, fmt.Errorf("failed to read 'display_name' field: %s", err.Error())
	}
	disabled, err := userJSON.GetBool("disabled")
	if err != nil {
		return userStruct{}, fmt.Errorf("failed to read 'disabled' field: %s", err.Error())
	}
	emailAddressCounter, err := userJSON.GetInt32("email_address_counter")
	if err != nil {
		return userStruct{}, fmt.Errorf("failed to read 'email_address_counter' field: %s", err.Error())
	}
	passwordHashCounter, err := userJSON.GetInt32("password_hash_counter")
	if err != nil {
		return userStruct{}, fmt.Errorf("failed to read 'password_hash_counter' field: %s", err.Error())
	}
	disabledCounter, err := userJSON.GetInt32("disabled_counter")
	if err != nil {
		return userStruct{}, fmt.Errorf("failed to read 'disabled_counter' field: %s", err.Error())
	}
	sessionsCounter, err := userJSON.GetInt32("sessions_counter")
	if err != nil {
		return userStruct{}, fmt.Errorf("failed to read 'sessions_counter' field: %s", err.Error())
	}

	passwordHash, err := base64.StdEncoding.DecodeString(encodedPasswordHash)
	if err != nil {
		return userStruct{}, fmt.Errorf("failed to decode password hash: %s", err.Error())
	}
	passwordSalt, err := base64.StdEncoding.DecodeString(encodedPasswordSalt)
	if err != nil {
		return userStruct{}, fmt.Errorf("failed to decode password salt: %s", err.Error())
	}

	user := userStruct{
		id:                      userId,
		emailAddress:            emailAddress,
		passwordHash:            passwordHash,
		passwordSalt:            passwordSalt,
		passwordHashAlgorithmId: passwordHashAlgorithmId,
		displayName:             displayName,
		disabled:                disabled,
		emailAddressCounter:     emailAddressCounter,
		passwordHashCounter:     passwordHashCounter,
		disabledCounter:         disabledCounter,
		sessionsCounter:         sessionsCounter,
	}

	return user, nil
}
