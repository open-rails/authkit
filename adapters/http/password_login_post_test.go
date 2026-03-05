package authhttp

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRecoverPendingEmailLogin_SuccessWhenVerificationDisabled(t *testing.T) {
	now := time.Now().UTC().Round(time.Second)
	createCalls := 0
	retryCalls := 0

	tok, exp, responseErr, handled := recoverPendingEmailLogin(
		true,
		true,
		false,
		func() error {
			createCalls++
			return nil
		},
		func() (string, time.Time, error) {
			retryCalls++
			return "access-token", now, nil
		},
	)

	require.True(t, handled)
	require.Empty(t, responseErr)
	require.Equal(t, "access-token", tok)
	require.Equal(t, now, exp)
	require.Equal(t, 1, createCalls)
	require.Equal(t, 1, retryCalls)
}

func TestRecoverPendingEmailLogin_ReturnsEmailNotVerifiedWhenVerificationRequired(t *testing.T) {
	createCalls := 0
	retryCalls := 0

	tok, exp, responseErr, handled := recoverPendingEmailLogin(
		true,
		true,
		true,
		func() error {
			createCalls++
			return nil
		},
		func() (string, time.Time, error) {
			retryCalls++
			return "", time.Time{}, nil
		},
	)

	require.True(t, handled)
	require.Equal(t, "email_not_verified", responseErr)
	require.Empty(t, tok)
	require.True(t, exp.IsZero())
	require.Equal(t, 1, createCalls)
	require.Equal(t, 0, retryCalls)
}

func TestRecoverPendingEmailLogin_ReturnsInvalidCredentialsOnRetryFailure(t *testing.T) {
	createCalls := 0
	retryCalls := 0

	tok, exp, responseErr, handled := recoverPendingEmailLogin(
		true,
		true,
		false,
		func() error {
			createCalls++
			return nil
		},
		func() (string, time.Time, error) {
			retryCalls++
			return "", time.Time{}, errors.New("login failed")
		},
	)

	require.True(t, handled)
	require.Equal(t, "invalid_credentials", responseErr)
	require.Empty(t, tok)
	require.True(t, exp.IsZero())
	require.Equal(t, 1, createCalls)
	require.Equal(t, 1, retryCalls)
}

func TestRecoverPendingEmailLogin_NotHandledWithoutPendingRecord(t *testing.T) {
	createCalls := 0
	retryCalls := 0

	tok, exp, responseErr, handled := recoverPendingEmailLogin(
		false,
		false,
		false,
		func() error {
			createCalls++
			return nil
		},
		func() (string, time.Time, error) {
			retryCalls++
			return "", time.Time{}, nil
		},
	)

	require.False(t, handled)
	require.Empty(t, responseErr)
	require.Empty(t, tok)
	require.True(t, exp.IsZero())
	require.Equal(t, 0, createCalls)
	require.Equal(t, 0, retryCalls)
}

func TestRecoverPendingPhoneLogin_SuccessWhenVerificationDisabled(t *testing.T) {
	createCalls := 0
	loadCalls := 0

	userID, responseErr, handled := recoverPendingPhoneLogin(
		true,
		true,
		false,
		func() error {
			createCalls++
			return nil
		},
		func() (string, error) {
			loadCalls++
			return "user-123", nil
		},
	)

	require.True(t, handled)
	require.Empty(t, responseErr)
	require.Equal(t, "user-123", userID)
	require.Equal(t, 1, createCalls)
	require.Equal(t, 1, loadCalls)
}

func TestRecoverPendingPhoneLogin_ReturnsPhoneNotVerifiedWhenVerificationRequired(t *testing.T) {
	createCalls := 0
	loadCalls := 0

	userID, responseErr, handled := recoverPendingPhoneLogin(
		true,
		true,
		true,
		func() error {
			createCalls++
			return nil
		},
		func() (string, error) {
			loadCalls++
			return "user-123", nil
		},
	)

	require.True(t, handled)
	require.Equal(t, "phone_not_verified", responseErr)
	require.Empty(t, userID)
	require.Equal(t, 1, createCalls)
	require.Equal(t, 0, loadCalls)
}

func TestRecoverPendingPhoneLogin_ReturnsInvalidCredentialsOnCreateFailure(t *testing.T) {
	createCalls := 0
	loadCalls := 0

	userID, responseErr, handled := recoverPendingPhoneLogin(
		true,
		true,
		false,
		func() error {
			createCalls++
			return errors.New("create failed")
		},
		func() (string, error) {
			loadCalls++
			return "user-123", nil
		},
	)

	require.True(t, handled)
	require.Equal(t, "invalid_credentials", responseErr)
	require.Empty(t, userID)
	require.Equal(t, 1, createCalls)
	require.Equal(t, 0, loadCalls)
}

func TestRecoverPendingPhoneLogin_NotHandledWithoutPendingRecord(t *testing.T) {
	createCalls := 0
	loadCalls := 0

	userID, responseErr, handled := recoverPendingPhoneLogin(
		false,
		false,
		false,
		func() error {
			createCalls++
			return nil
		},
		func() (string, error) {
			loadCalls++
			return "user-123", nil
		},
	)

	require.False(t, handled)
	require.Empty(t, responseErr)
	require.Empty(t, userID)
	require.Equal(t, 0, createCalls)
	require.Equal(t, 0, loadCalls)
}
