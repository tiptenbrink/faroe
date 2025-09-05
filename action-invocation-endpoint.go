package faroe

import (
	"fmt"
	"slices"

	"github.com/faroedev/go-json"
)

// Resolves an action invocation endpoint request, accepting all actions except for ones in the blocklist.
// Returns the string body of a 200 response or an error if the request is invalid.
func (server *ServerStruct) ResolveActionInvocationEndpointRequestWithBlocklist(bodyJSON string, blocklist []string) (string, error) {
	bodyJSONObject, err := json.ParseObject(bodyJSON)
	if err != nil {
		return "", fmt.Errorf("failed to parse json body")
	}

	action, err := bodyJSONObject.GetString("action")
	if err != nil {
		return "", fmt.Errorf("failed to read 'action' field from body json object: %s", err.Error())
	}

	argumentsJSONObject, err := bodyJSONObject.GetJSONObject("arguments")
	if err != nil {
		return "", fmt.Errorf("failed to read 'action' field from body json object: %s", err.Error())
	}

	if slices.Contains(blocklist, action) {
		return "", fmt.Errorf("action %s in blocklist", action)
	}

	resultJSON, err := server.invokeAction(action, argumentsJSONObject)
	if err != nil {
		return "", fmt.Errorf("failed to invoke action: %s", err.Error())
	}

	return resultJSON, nil
}

// Resolves an action invocation endpoint request, only accepting actions in the allowlist.
// Returns the string body of a 200 response or an error if the request is invalid.
func (server *ServerStruct) ResolveActionInvocationEndpointRequestWithAllowlist(bodyJSON string, allowlist []string) (string, error) {
	bodyJSONObject, err := json.ParseObject(bodyJSON)
	if err != nil {
		return "", fmt.Errorf("failed to parse json body")
	}

	action, err := bodyJSONObject.GetString("action")
	if err != nil {
		return "", fmt.Errorf("failed to read 'action' field from body json object: %s", err.Error())
	}

	argumentsJSONObject, err := bodyJSONObject.GetJSONObject("arguments")
	if err != nil {
		return "", fmt.Errorf("failed to read 'action' field from body json object: %s", err.Error())
	}

	if !slices.Contains(allowlist, action) {
		return "", fmt.Errorf("action %s not in allowlist", action)
	}

	resultJSON, err := server.invokeAction(action, argumentsJSONObject)
	if err != nil {
		return "", fmt.Errorf("failed to invoke action: %s", err.Error())
	}

	return resultJSON, nil
}

func (server *ServerStruct) invokeAction(action string, argumentsJSONObject json.ObjectStruct) (string, error) {
	switch action {
	case ActionCreateSignup:
		return server.invokeCreateSignupAction(argumentsJSONObject)
	case ActionGetSignup:
		return server.invokeGetSignupAction(argumentsJSONObject)
	case ActionDeleteSignup:
		return server.invokeDeleteSignupAction(argumentsJSONObject)
	case ActionSendSignupEmailAddressVerificationCode:
		return server.invokeSendSignupEmailAddressVerificationCodeAction(argumentsJSONObject)
	case ActionVerifySignupEmailAddressVerificationCode:
		return server.invokeVerifySignupEmailAddressVerificationCodeAction(argumentsJSONObject)
	case ActionSetSignupPassword:
		return server.invokeSetSignupPasswordAction(argumentsJSONObject)
	case ActionCompleteSignup:
		return server.invokeCompleteSignupAction(argumentsJSONObject)

	case ActionCreateSignin:
		return server.invokeCreateSigninAction(argumentsJSONObject)
	case ActionGetSignin:
		return server.invokeGetSigninAction(argumentsJSONObject)
	case ActionDeleteSignin:
		return server.invokeDeleteSigninAction(argumentsJSONObject)
	case ActionVerifySigninUserPassword:
		return server.invokeVerifySigninUserPasswordAction(argumentsJSONObject)
	case ActionCompleteSignin:
		return server.invokeCompleteSigninAction(argumentsJSONObject)

	case ActionGetSession:
		return server.invokeGetSessionAction(argumentsJSONObject)
	case ActionDeleteSession:
		return server.invokeDeleteSessionAction(argumentsJSONObject)
	case ActionDeleteAllSessions:
		return server.invokeDeleteAllSessionsAction(argumentsJSONObject)

	case ActionCreateUserEmailAddressUpdate:
		return server.invokeCreateUserEmailAddressUpdateAction(argumentsJSONObject)
	case ActionGetUserEmailAddressUpdate:
		return server.invokeGetUserEmailAddressUpdateAction(argumentsJSONObject)
	case ActionDeleteUserEmailAddressUpdate:
		return server.invokeDeleteUserEmailAddressUpdateAction(argumentsJSONObject)
	case ActionSendUserEmailAddressUpdateEmailAddressVerificationCode:
		return server.invokeSendUserEmailAddressUpdateEmailAddressVerificationCodeAction(argumentsJSONObject)
	case ActionVerifyUserEmailAddressUpdateEmailAddressVerificationCode:
		return server.invokeVerifyUserEmailAddressUpdateEmailAddressVerificationCodeAction(argumentsJSONObject)
	case ActionVerifyUserEmailAddressUpdateUserPassword:
		return server.invokeVerifyUserEmailAddressUpdateUserPasswordAction(argumentsJSONObject)
	case ActionCompleteUserEmailAddressUpdate:
		return server.invokeCompleteUserEmailAddressUpdateAction(argumentsJSONObject)

	case ActionCreateUserPasswordUpdate:
		return server.invokeCreateUserPasswordUpdateAction(argumentsJSONObject)
	case ActionGetUserPasswordUpdate:
		return server.invokeGetUserPasswordUpdateAction(argumentsJSONObject)
	case ActionDeleteUserPasswordUpdate:
		return server.invokeDeleteUserPasswordUpdateAction(argumentsJSONObject)
	case ActionVerifyUserPasswordUpdateUserPassword:
		return server.invokeVerifyUserPasswordUpdateUserPasswordAction(argumentsJSONObject)
	case ActionSetUserPasswordUpdateNewPassword:
		return server.invokeSetUserPasswordUpdateNewPasswordAction(argumentsJSONObject)
	case ActionCompleteUserPasswordUpdate:
		return server.invokeCompleteUserPasswordUpdateAction(argumentsJSONObject)

	case ActionCreateUserDeletion:
		return server.invokeCreateUserDeletionAction(argumentsJSONObject)
	case ActionGetUserDeletion:
		return server.invokeGetUserDeletionAction(argumentsJSONObject)
	case ActionDeleteUserDeletion:
		return server.invokeDeleteUserDeletionAction(argumentsJSONObject)
	case ActionVerifyUserDeletionUserPassword:
		return server.invokeVerifyUserDeletionUserPasswordAction(argumentsJSONObject)
	case ActionCompleteUserDeletion:
		return server.invokeCompleteUserDeletionAction(argumentsJSONObject)

	case ActionCreateUserPasswordReset:
		return server.invokeCreateUserPasswordResetAction(argumentsJSONObject)
	case ActionGetUserPasswordReset:
		return server.invokeGetUserPasswordResetAction(argumentsJSONObject)
	case ActionDeleteUserPasswordReset:
		return server.invokeDeleteUserPasswordResetAction(argumentsJSONObject)
	case ActionVerifyUserPasswordResetTemporaryPassword:
		return server.invokeVerifyUserPasswordResetTemporaryPasswordAction(argumentsJSONObject)
	case ActionSetUserPasswordResetNewPassword:
		return server.invokeSetUserPasswordResetNewPasswordAction(argumentsJSONObject)
	case ActionCompleteUserPasswordReset:
		return server.invokeCompleteUserPasswordResetAction(argumentsJSONObject)

	default:
		return "", fmt.Errorf("unknown action %s", action)
	}
}

func (server *ServerStruct) invokeCreateSignupAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	emailAddress, err := argumentsJSONObject.GetString("email_address")
	if err != nil {
		return "", fmt.Errorf("failed to read 'email_address' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	signup, signupToken, err := server.createSignupAction(actionInvocationId, emailAddress)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	signupJSON := server.encodeSignupToJSON(signup)

	valuesJSONBuilder := json.NewObjectBuilder()
	valuesJSONBuilder.AddJSON("signup", signupJSON)
	valuesJSONBuilder.AddString("signup_token", signupToken)
	valuesJSON := valuesJSONBuilder.Done()

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, valuesJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeGetSignupAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	signupToken, err := argumentsJSONObject.GetString("signup_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'signup_token' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	signup, err := server.getSignupAction(actionInvocationId, signupToken)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	signupJSON := server.encodeSignupToJSON(signup)

	valuesJSONBuilder := json.NewObjectBuilder()
	valuesJSONBuilder.AddJSON("signup", signupJSON)
	valuesJSON := valuesJSONBuilder.Done()

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, valuesJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeDeleteSignupAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	signupToken, err := argumentsJSONObject.GetString("signup_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'signup_token' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	err = server.deleteSignupAction(actionInvocationId, signupToken)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, emptyObjectJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeSendSignupEmailAddressVerificationCodeAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	signupToken, err := argumentsJSONObject.GetString("signup_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'signup_token' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	err = server.sendSignupEmailAddressVerificationCodeAction(actionInvocationId, signupToken)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, emptyObjectJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeVerifySignupEmailAddressVerificationCodeAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	signupToken, err := argumentsJSONObject.GetString("signup_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'signup_token' field from arguments json object: %s", err.Error())
	}

	emailAddressVerificationCode, err := argumentsJSONObject.GetString("email_address_verification_code")
	if err != nil {
		return "", fmt.Errorf("failed to read 'email_address_verification_code' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	err = server.verifySignupEmailAddressVerificationCodeAction(
		actionInvocationId,
		signupToken,
		emailAddressVerificationCode,
	)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, emptyObjectJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeSetSignupPasswordAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	signupToken, err := argumentsJSONObject.GetString("signup_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'signup_token' field from arguments json object: %s", err.Error())
	}

	password, err := argumentsJSONObject.GetString("password")
	if err != nil {
		return "", fmt.Errorf("failed to read 'password' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	err = server.setSignupPasswordAction(actionInvocationId, signupToken, password)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, emptyObjectJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeCompleteSignupAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	signupToken, err := argumentsJSONObject.GetString("signup_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'signup_token' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	session, sessionToken, err := server.completeSignupAction(actionInvocationId, signupToken)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	sessionJSON := server.encodeSessionToJSON(session)

	valuesJSONBuilder := json.NewObjectBuilder()
	valuesJSONBuilder.AddJSON("session", sessionJSON)
	valuesJSONBuilder.AddString("session_token", sessionToken)
	valuesJSON := valuesJSONBuilder.Done()

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, valuesJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeCreateSigninAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	userEmailAddress, err := argumentsJSONObject.GetString("user_email_address")
	if err != nil {
		return "", fmt.Errorf("failed to read 'user_email_address' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	signin, signinToken, err := server.createSigninAction(actionInvocationId, userEmailAddress)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	signinJSON := server.encodeSigninToJSON(signin)

	valuesJSONBuilder := json.NewObjectBuilder()
	valuesJSONBuilder.AddJSON("signin", signinJSON)
	valuesJSONBuilder.AddString("signin_token", signinToken)
	valuesJSON := valuesJSONBuilder.Done()

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, valuesJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeGetSigninAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	signinToken, err := argumentsJSONObject.GetString("signin_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'signin_token' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	signin, err := server.getSigninAction(actionInvocationId, signinToken)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	signinJSON := server.encodeSigninToJSON(signin)

	valuesJSONBuilder := json.NewObjectBuilder()
	valuesJSONBuilder.AddJSON("signin", signinJSON)
	valuesJSON := valuesJSONBuilder.Done()

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, valuesJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeDeleteSigninAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	signinToken, err := argumentsJSONObject.GetString("signin_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'signin_token' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	err = server.deleteSigninAction(actionInvocationId, signinToken)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, emptyObjectJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeVerifySigninUserPasswordAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	signinToken, err := argumentsJSONObject.GetString("signin_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'signin_token' field from arguments json object: %s", err.Error())
	}

	password, err := argumentsJSONObject.GetString("password")
	if err != nil {
		return "", fmt.Errorf("failed to read 'password' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	err = server.verifySigninUserPasswordAction(actionInvocationId, signinToken, password)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, emptyObjectJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeCompleteSigninAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	signinToken, err := argumentsJSONObject.GetString("signin_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'signin_token' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	session, sessionToken, err := server.completeSigninAction(actionInvocationId, signinToken)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	sessionJSON := server.encodeSessionToJSON(session)

	valuesJSONBuilder := json.NewObjectBuilder()
	valuesJSONBuilder.AddJSON("session", sessionJSON)
	valuesJSONBuilder.AddString("session_token", sessionToken)
	valuesJSON := valuesJSONBuilder.Done()

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, valuesJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeGetSessionAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	sessionToken, err := argumentsJSONObject.GetString("session_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'session_token' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	session, err := server.getSessionAction(actionInvocationId, sessionToken)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	sessionJSON := server.encodeSessionToJSON(session)

	valuesJSONBuilder := json.NewObjectBuilder()
	valuesJSONBuilder.AddJSON("session", sessionJSON)
	valuesJSON := valuesJSONBuilder.Done()

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, valuesJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeDeleteSessionAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	sessionToken, err := argumentsJSONObject.GetString("session_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'session_token' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	err = server.deleteSessionAction(actionInvocationId, sessionToken)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, emptyObjectJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeDeleteAllSessionsAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	sessionToken, err := argumentsJSONObject.GetString("session_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'session_token' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	err = server.deleteAllSessionsAction(actionInvocationId, sessionToken)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, emptyObjectJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeCreateUserEmailAddressUpdateAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	sessionToken, err := argumentsJSONObject.GetString("session_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'session_token' field from arguments json object: %s", err.Error())
	}
	newEmailAddress, err := argumentsJSONObject.GetString("new_email_address")
	if err != nil {
		return "", fmt.Errorf("failed to read 'new_email_address' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	userEmailAddressUpdate, userEmailAddressUpdateToken, err := server.createUserEmailAddressUpdateAction(actionInvocationId, sessionToken, newEmailAddress)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	userEmailAddressUpdateJSON := server.encodeUserEmailAddressUpdateToJSON(userEmailAddressUpdate)

	valuesJSONBuilder := json.NewObjectBuilder()
	valuesJSONBuilder.AddJSON("user_email_address_update", userEmailAddressUpdateJSON)
	valuesJSONBuilder.AddString("user_email_address_update_token", userEmailAddressUpdateToken)
	valuesJSON := valuesJSONBuilder.Done()

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, valuesJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeGetUserEmailAddressUpdateAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	sessionToken, err := argumentsJSONObject.GetString("session_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'session_token' field from arguments json object: %s", err.Error())
	}
	userEmailAddressUpdateToken, err := argumentsJSONObject.GetString("user_email_address_update_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'user_email_address_update_token' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	userEmailAddressUpdate, err := server.getUserEmailAddressUpdateAction(actionInvocationId, sessionToken, userEmailAddressUpdateToken)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	userEmailAddressUpdateJSON := server.encodeUserEmailAddressUpdateToJSON(userEmailAddressUpdate)

	valuesJSONBuilder := json.NewObjectBuilder()
	valuesJSONBuilder.AddJSON("user_email_address_update", userEmailAddressUpdateJSON)
	valuesJSON := valuesJSONBuilder.Done()

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, valuesJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeDeleteUserEmailAddressUpdateAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	sessionToken, err := argumentsJSONObject.GetString("session_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'session_token' field from arguments json object: %s", err.Error())
	}
	userEmailAddressUpdateToken, err := argumentsJSONObject.GetString("user_email_address_update_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'user_email_address_update_token' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	err = server.deleteUserEmailAddressUpdateAction(actionInvocationId, sessionToken, userEmailAddressUpdateToken)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, emptyObjectJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeSendUserEmailAddressUpdateEmailAddressVerificationCodeAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	sessionToken, err := argumentsJSONObject.GetString("session_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'session_token' field from arguments json object: %s", err.Error())
	}
	userEmailAddressUpdateToken, err := argumentsJSONObject.GetString("user_email_address_update_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'user_email_address_update_token' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	err = server.sendUserEmailAddressUpdateEmailAddressVerificationCodeAction(actionInvocationId, sessionToken, userEmailAddressUpdateToken)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, emptyObjectJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeVerifyUserEmailAddressUpdateEmailAddressVerificationCodeAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	sessionToken, err := argumentsJSONObject.GetString("session_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'session_token' field from arguments json object: %s", err.Error())
	}
	userEmailAddressUpdateToken, err := argumentsJSONObject.GetString("user_email_address_update_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'user_email_address_update_token' field from arguments json object: %s", err.Error())
	}
	emailAddressVerificationCode, err := argumentsJSONObject.GetString("email_address_verification_code")
	if err != nil {
		return "", fmt.Errorf("failed to read 'email_address_verification_code' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	err = server.verifyUserEmailAddressUpdateEmailAddressVerificationCodeAction(actionInvocationId, sessionToken, userEmailAddressUpdateToken, emailAddressVerificationCode)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, emptyObjectJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeVerifyUserEmailAddressUpdateUserPasswordAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	sessionToken, err := argumentsJSONObject.GetString("session_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'session_token' field from arguments json object: %s", err.Error())
	}
	userEmailAddressUpdateToken, err := argumentsJSONObject.GetString("user_email_address_update_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'user_email_address_update_token' field from arguments json object: %s", err.Error())
	}
	password, err := argumentsJSONObject.GetString("password")
	if err != nil {
		return "", fmt.Errorf("failed to read 'password' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	err = server.verifyUserEmailAddressUpdateUserPasswordAction(actionInvocationId, sessionToken, userEmailAddressUpdateToken, password)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, emptyObjectJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeCompleteUserEmailAddressUpdateAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	sessionToken, err := argumentsJSONObject.GetString("session_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'session_token' field from arguments json object: %s", err.Error())
	}
	userEmailAddressUpdateToken, err := argumentsJSONObject.GetString("user_email_address_update_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'user_email_address_update_token' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	err = server.completeUserEmailAddressUpdateAction(actionInvocationId, sessionToken, userEmailAddressUpdateToken)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, emptyObjectJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeCreateUserPasswordUpdateAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	sessionToken, err := argumentsJSONObject.GetString("session_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'session_token' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	userPasswordUpdate, userPasswordUpdateToken, err := server.createUserPasswordUpdateAction(actionInvocationId, sessionToken)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	userPasswordUpdateJSON := server.encodeUserPasswordUpdateToJSON(userPasswordUpdate)

	valuesJSONBuilder := json.NewObjectBuilder()
	valuesJSONBuilder.AddJSON("user_password_update", userPasswordUpdateJSON)
	valuesJSONBuilder.AddString("user_password_update_token", userPasswordUpdateToken)
	valuesJSON := valuesJSONBuilder.Done()

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, valuesJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeGetUserPasswordUpdateAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	sessionToken, err := argumentsJSONObject.GetString("session_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'session_token' field from arguments json object: %s", err.Error())
	}
	userPasswordUpdateToken, err := argumentsJSONObject.GetString("user_password_update_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'user_password_update_token' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	userPasswordUpdate, err := server.getUserPasswordUpdateAction(actionInvocationId, sessionToken, userPasswordUpdateToken)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	userPasswordUpdateJSON := server.encodeUserPasswordUpdateToJSON(userPasswordUpdate)

	valuesJSONBuilder := json.NewObjectBuilder()
	valuesJSONBuilder.AddJSON("user_password_update", userPasswordUpdateJSON)
	valuesJSON := valuesJSONBuilder.Done()

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, valuesJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeDeleteUserPasswordUpdateAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	sessionToken, err := argumentsJSONObject.GetString("session_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'session_token' field from arguments json object: %s", err.Error())
	}
	userPasswordUpdateToken, err := argumentsJSONObject.GetString("user_password_update_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'user_password_update_token' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	err = server.deleteUserPasswordUpdateAction(actionInvocationId, sessionToken, userPasswordUpdateToken)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, emptyObjectJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeVerifyUserPasswordUpdateUserPasswordAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	sessionToken, err := argumentsJSONObject.GetString("session_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'session_token' field from arguments json object: %s", err.Error())
	}
	userPasswordUpdateToken, err := argumentsJSONObject.GetString("user_password_update_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'user_password_update_token' field from arguments json object: %s", err.Error())
	}
	password, err := argumentsJSONObject.GetString("password")
	if err != nil {
		return "", fmt.Errorf("failed to read 'password' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	err = server.verifyUserPasswordUpdateUserPasswordAction(actionInvocationId, sessionToken, userPasswordUpdateToken, password)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, emptyObjectJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeSetUserPasswordUpdateNewPasswordAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	sessionToken, err := argumentsJSONObject.GetString("session_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'session_token' field from arguments json object: %s", err.Error())
	}
	userPasswordUpdateToken, err := argumentsJSONObject.GetString("user_password_update_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'user_password_update_token' field from arguments json object: %s", err.Error())
	}
	password, err := argumentsJSONObject.GetString("password")
	if err != nil {
		return "", fmt.Errorf("failed to read 'password' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	err = server.setUserPasswordUpdateNewPasswordAction(actionInvocationId, sessionToken, userPasswordUpdateToken, password)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, emptyObjectJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeCompleteUserPasswordUpdateAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	sessionToken, err := argumentsJSONObject.GetString("session_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'session_token' field from arguments json object: %s", err.Error())
	}
	userPasswordUpdateToken, err := argumentsJSONObject.GetString("user_password_update_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'user_password_update_token' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	err = server.completeUserPasswordUpdateAction(actionInvocationId, sessionToken, userPasswordUpdateToken)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, emptyObjectJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeCreateUserDeletionAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	sessionToken, err := argumentsJSONObject.GetString("session_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'session_token' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	userDeletion, userDeletionToken, err := server.createUserDeletionAction(actionInvocationId, sessionToken)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	userDeletionJSON := server.encodeUserDeletionToJSON(userDeletion)

	valuesJSONBuilder := json.NewObjectBuilder()
	valuesJSONBuilder.AddJSON("user_deletion", userDeletionJSON)
	valuesJSONBuilder.AddString("user_deletion_token", userDeletionToken)
	valuesJSON := valuesJSONBuilder.Done()

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, valuesJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeGetUserDeletionAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	sessionToken, err := argumentsJSONObject.GetString("session_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'session_token' field from arguments json object: %s", err.Error())
	}
	userDeletionToken, err := argumentsJSONObject.GetString("user_deletion_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'user_deletion_token' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	userDeletion, err := server.getUserDeletionAction(actionInvocationId, sessionToken, userDeletionToken)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	userDeletionJSON := server.encodeUserDeletionToJSON(userDeletion)

	valuesJSONBuilder := json.NewObjectBuilder()
	valuesJSONBuilder.AddJSON("user_deletion", userDeletionJSON)
	valuesJSON := valuesJSONBuilder.Done()

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, valuesJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeDeleteUserDeletionAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	sessionToken, err := argumentsJSONObject.GetString("session_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'session_token' field from arguments json object: %s", err.Error())
	}
	userDeletionToken, err := argumentsJSONObject.GetString("user_deletion_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'user_deletion_token' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	err = server.deleteUserDeletionAction(actionInvocationId, sessionToken, userDeletionToken)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, emptyObjectJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeVerifyUserDeletionUserPasswordAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	sessionToken, err := argumentsJSONObject.GetString("session_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'session_token' field from arguments json object: %s", err.Error())
	}
	userDeletionToken, err := argumentsJSONObject.GetString("user_deletion_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'user_deletion_token' field from arguments json object: %s", err.Error())
	}
	password, err := argumentsJSONObject.GetString("password")
	if err != nil {
		return "", fmt.Errorf("failed to read 'password' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	err = server.verifyUserDeletionUserPasswordAction(actionInvocationId, sessionToken, userDeletionToken, password)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, emptyObjectJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeCompleteUserDeletionAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	sessionToken, err := argumentsJSONObject.GetString("session_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'session_token' field from arguments json object: %s", err.Error())
	}
	userDeletionToken, err := argumentsJSONObject.GetString("user_deletion_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'user_deletion_token' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	err = server.completeUserDeletionAction(actionInvocationId, sessionToken, userDeletionToken)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, emptyObjectJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeCreateUserPasswordResetAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	userEmailAddress, err := argumentsJSONObject.GetString("user_email_address")
	if err != nil {
		return "", fmt.Errorf("failed to read 'user_email_address' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	userPasswordReset, userPasswordResetToken, err := server.createUserPasswordResetAction(actionInvocationId, userEmailAddress)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	userPasswordResetJSON := server.encodeUserPasswordResetToJSON(userPasswordReset)

	valuesJSONBuilder := json.NewObjectBuilder()
	valuesJSONBuilder.AddJSON("user_password_reset", userPasswordResetJSON)
	valuesJSONBuilder.AddString("user_password_reset_token", userPasswordResetToken)
	valuesJSON := valuesJSONBuilder.Done()

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, valuesJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeGetUserPasswordResetAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	userPasswordResetToken, err := argumentsJSONObject.GetString("user_password_reset_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'user_password_reset_token' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	userPasswordReset, err := server.getUserPasswordResetAction(actionInvocationId, userPasswordResetToken)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	userPasswordResetJSON := server.encodeUserPasswordResetToJSON(userPasswordReset)

	valuesJSONBuilder := json.NewObjectBuilder()
	valuesJSONBuilder.AddJSON("user_password_reset", userPasswordResetJSON)
	valuesJSON := valuesJSONBuilder.Done()

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, valuesJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeDeleteUserPasswordResetAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	userPasswordResetToken, err := argumentsJSONObject.GetString("user_password_reset_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'user_password_reset_token' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	err = server.deleteUserPasswordResetAction(actionInvocationId, userPasswordResetToken)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, emptyObjectJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeVerifyUserPasswordResetTemporaryPasswordAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	userPasswordResetToken, err := argumentsJSONObject.GetString("user_password_reset_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'user_password_reset_token' field from arguments json object: %s", err.Error())
	}
	temporaryPassword, err := argumentsJSONObject.GetString("temporary_password")
	if err != nil {
		return "", fmt.Errorf("failed to read 'temporary_password' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	err = server.verifyUserPasswordResetTemporaryPasswordAction(actionInvocationId, userPasswordResetToken, temporaryPassword)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, emptyObjectJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeSetUserPasswordResetNewPasswordAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	userPasswordResetToken, err := argumentsJSONObject.GetString("user_password_reset_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'user_password_reset_token' field from arguments json object: %s", err.Error())
	}
	password, err := argumentsJSONObject.GetString("password")
	if err != nil {
		return "", fmt.Errorf("failed to read 'password' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	err = server.setUserPasswordResetNewPasswordAction(actionInvocationId, userPasswordResetToken, password)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, emptyObjectJSON)

	return resultJSON, nil
}

func (server *ServerStruct) invokeCompleteUserPasswordResetAction(argumentsJSONObject json.ObjectStruct) (string, error) {
	userPasswordResetToken, err := argumentsJSONObject.GetString("user_password_reset_token")
	if err != nil {
		return "", fmt.Errorf("failed to read 'user_password_reset_token' field from arguments json object: %s", err.Error())
	}

	actionInvocationId := generateRandomId()

	session, sessionToken, err := server.completeUserPasswordResetAction(actionInvocationId, userPasswordResetToken)
	if err != nil {
		actionErr := err.(*actionErrorStruct)

		resultJSON := createActionInvocationEndpointActionErrorResultJSON(actionInvocationId, actionErr.errorCode)
		return resultJSON, nil
	}

	sessionJSON := server.encodeSessionToJSON(session)

	valuesJSONBuilder := json.NewObjectBuilder()
	valuesJSONBuilder.AddJSON("session", sessionJSON)
	valuesJSONBuilder.AddString("session_token", sessionToken)
	valuesJSON := valuesJSONBuilder.Done()

	resultJSON := createActionInvocationSuccessResultJSON(actionInvocationId, valuesJSON)

	return resultJSON, nil
}

func (server *ServerStruct) encodeSignupToJSON(signup actionSignupStruct) string {
	builder := json.NewObjectBuilder()
	builder.AddString("id", signup.id)
	builder.AddString("unregistered_user_id", signup.unregisteredUserId)
	builder.AddString("email_address", signup.emailAddress)
	builder.AddBool("email_address_verified", signup.emailAddressVerified)
	builder.AddBool("password_set", signup.passwordSet)
	builder.AddInt64("created_at", signup.createdAt.Unix())
	builder.AddInt64("expires_at", signup.expiresAt.Unix())
	return builder.Done()
}

func (server *ServerStruct) encodeSigninToJSON(signin actionSigninStruct) string {
	builder := json.NewObjectBuilder()
	builder.AddString("id", signin.id)
	builder.AddString("user_id", signin.userId)
	builder.AddBool("user_first_factor_verified", signin.userFirstFactorVerified)
	builder.AddInt64("created_at", signin.createdAt.Unix())
	builder.AddInt64("expires_at", signin.expiresAt.Unix())
	return builder.Done()
}

func (server *ServerStruct) encodeSessionToJSON(session actionSessionStruct) string {
	builder := json.NewObjectBuilder()
	builder.AddString("id", session.id)
	builder.AddString("user_id", session.userId)
	builder.AddInt64("created_at", session.createdAt.Unix())
	if session.expiresAtDefined {
		builder.AddInt64("expires_at", session.expiresAt.Unix())
	} else {
		builder.AddNull("expires_at")
	}
	return builder.Done()
}

func (server *ServerStruct) encodeUserEmailAddressUpdateToJSON(userEmailAddressUpdate actionUserEmailAddressUpdateStruct) string {
	builder := json.NewObjectBuilder()
	builder.AddString("id", userEmailAddressUpdate.id)
	builder.AddString("user_id", userEmailAddressUpdate.userId)
	builder.AddString("session_id", userEmailAddressUpdate.sessionId)
	builder.AddString("new_email_address", userEmailAddressUpdate.newEmailAddress)
	builder.AddBool("new_email_address_verified", userEmailAddressUpdate.newEmailAddressVerified)
	builder.AddBool("user_identity_verified", userEmailAddressUpdate.userIdentityVerified)
	builder.AddInt64("created_at", userEmailAddressUpdate.createdAt.Unix())
	builder.AddInt64("expires_at", userEmailAddressUpdate.expiresAt.Unix())
	return builder.Done()
}

func (server *ServerStruct) encodeUserPasswordUpdateToJSON(userPasswordUpdate actionUserPasswordUpdateStruct) string {
	builder := json.NewObjectBuilder()
	builder.AddString("id", userPasswordUpdate.id)
	builder.AddString("user_id", userPasswordUpdate.userId)
	builder.AddString("session_id", userPasswordUpdate.sessionId)
	builder.AddBool("user_identity_verified", userPasswordUpdate.userIdentityVerified)
	builder.AddBool("new_password_set", userPasswordUpdate.newPasswordSet)
	builder.AddInt64("created_at", userPasswordUpdate.createdAt.Unix())
	builder.AddInt64("expires_at", userPasswordUpdate.expiresAt.Unix())
	return builder.Done()
}

func (server *ServerStruct) encodeUserDeletionToJSON(userDeletion actionUserDeletionStruct) string {
	builder := json.NewObjectBuilder()
	builder.AddString("id", userDeletion.id)
	builder.AddString("user_id", userDeletion.userId)
	builder.AddString("session_id", userDeletion.sessionId)
	builder.AddBool("user_identity_verified", userDeletion.userIdentityVerified)
	builder.AddInt64("created_at", userDeletion.createdAt.Unix())
	builder.AddInt64("expires_at", userDeletion.expiresAt.Unix())
	return builder.Done()
}

func (server *ServerStruct) encodeUserPasswordResetToJSON(userPasswordReset actionUserPasswordResetStruct) string {
	builder := json.NewObjectBuilder()
	builder.AddString("id", userPasswordReset.id)
	builder.AddString("user_id", userPasswordReset.userId)
	builder.AddBool("user_first_factor_verified", userPasswordReset.userFirstFactorVerified)
	builder.AddBool("new_password_set", userPasswordReset.newPasswordSet)
	builder.AddInt64("created_at", userPasswordReset.createdAt.Unix())
	builder.AddInt64("expires_at", userPasswordReset.expiresAt.Unix())
	return builder.Done()
}

func createActionInvocationSuccessResultJSON(actionInvocationCredentialId string, valuesJSON string) string {
	builder := json.NewObjectBuilder()
	builder.AddBool("ok", true)
	builder.AddString("action_invocation_id", actionInvocationCredentialId)
	builder.AddJSON("values", valuesJSON)
	resultJSON := builder.Done()
	return resultJSON
}

func createActionInvocationEndpointActionErrorResultJSON(actionInvocationCredentialId string, errorCode string) string {
	builder := json.NewObjectBuilder()
	builder.AddBool("ok", false)
	builder.AddString("action_invocation_id", actionInvocationCredentialId)
	builder.AddString("error_code", errorCode)
	resultJSON := builder.Done()
	return resultJSON
}

type actionInvocationActionErrorStruct struct {
	actionInvocationId string
	errorCode          string
}

func newActionInvocationActionError(actionInvocationId string, errorCode string) *actionInvocationActionErrorStruct {
	return &actionInvocationActionErrorStruct{actionInvocationId: actionInvocationId, errorCode: errorCode}
}

func (actionInvocationActionError *actionInvocationActionErrorStruct) Error() string {
	return actionInvocationActionError.errorCode
}

func sendActionInvocationRequest(actionInvocationEndpointClient ActionInvocationEndpointClientInterface, action string, argumentsJSON string) (string, json.ObjectStruct, error) {
	bodyJSONBuilder := json.NewObjectBuilder()
	bodyJSONBuilder.AddString("action", action)
	bodyJSONBuilder.AddJSON("arguments", argumentsJSON)
	bodyJSON := bodyJSONBuilder.Done()

	resultJSON, err := actionInvocationEndpointClient.SendActionInvocationEndpointRequest(bodyJSON)
	if err != nil {
		return "", json.ObjectStruct{}, fmt.Errorf("failed to send action invocation endpoint request: %s", err.Error())
	}

	resultJSONObject, err := json.ParseObject(resultJSON)
	if err != nil {
		return "", json.ObjectStruct{}, fmt.Errorf("failed to parse result json: %s", err.Error())
	}

	resultOk, err := resultJSONObject.GetBool("ok")
	if err != nil {
		return "", json.ObjectStruct{}, fmt.Errorf("failed to parse result json: %s", err.Error())
	}

	actionInvocationId, err := resultJSONObject.GetString("action_invocation_id")
	if err != nil {
		return "", json.ObjectStruct{}, fmt.Errorf("failed to read 'action_invocation_id' field from result object: %s", err.Error())
	}
	if !resultOk {
		errorCode, err := resultJSONObject.GetString("error_code")
		if err != nil {
			return "", json.ObjectStruct{}, fmt.Errorf("failed to read 'error_code' field from result object: %s", err.Error())
		}

		return "", json.ObjectStruct{}, newActionInvocationActionError(actionInvocationId, errorCode)
	}

	valuesJSONObject, err := resultJSONObject.GetJSONObject("values")
	if err != nil {
		return "", json.ObjectStruct{}, fmt.Errorf("failed to read 'values' field from result object: %s", err.Error())
	}

	return actionInvocationId, valuesJSONObject, nil
}
