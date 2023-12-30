package db

import (
	"context"
	"crypto/rand"
	"math/big"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func createTestSession(t *testing.T) Session {
	account := createTestAccount(t)
	require.NotEmpty(t, account)

	randomNum, err := rand.Int(rand.Reader, big.NewInt(2))
	require.NoError(t, err)

	// set client IP to either IPv4 or IPv6
	clientIP := gofakeit.IPv4Address()
	if randomNum.Int64() == 1 {
		clientIP = gofakeit.IPv6Address()
	}

	params := CreateSessionParams{
		ID:            uuid.New(),
		WalletAddress: account.Owner,
		// TODO: Set to actual token
		RefreshToken: uuid.New().String(),
		UserAgent:    gofakeit.UserAgent(),
		ClientIp:     clientIP,
		ExpiresAt:    time.Now().UTC().Add(3 * time.Hour),
	}

	session, err := testStore.CreateSession(context.Background(), params)
	require.NoError(t, err)
	require.NotEmpty(t, session)

	require.Equal(t, params.ID, session.ID)
	require.Equal(t, params.WalletAddress, session.WalletAddress)
	require.Equal(t, params.RefreshToken, session.RefreshToken)
	require.Equal(t, params.UserAgent, session.UserAgent)
	require.Equal(t, params.ClientIp, session.ClientIp)
	require.WithinDuration(t, params.ExpiresAt, session.ExpiresAt, time.Second)
	require.NotZero(t, session.CreatedAt)

	require.Equal(t, account.Owner, session.WalletAddress)

	require.False(t, session.IsRevoked)

	return session
}

func TestCreateSession(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test to maintain db state")
	}

	session := createTestSession(t)
	require.NotEmpty(t, session)
}

func TestGetSession(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test to maintain db state")
	}

	session := createTestSession(t)
	require.NotEmpty(t, session)

	fetchedSession, err := testStore.GetSession(context.Background(), session.ID)
	require.NoError(t, err)
	require.NotEmpty(t, fetchedSession)

	require.Equal(t, session.ID, fetchedSession.ID)
	require.Equal(t, session.WalletAddress, fetchedSession.WalletAddress)
	require.Equal(t, session.RefreshToken, fetchedSession.RefreshToken)
	require.Equal(t, session.UserAgent, fetchedSession.UserAgent)
	require.Equal(t, session.ClientIp, fetchedSession.ClientIp)
	require.Equal(t, session.IsRevoked, fetchedSession.IsRevoked)
	require.WithinDuration(t, session.ExpiresAt, fetchedSession.ExpiresAt, time.Second)
	require.WithinDuration(t, session.CreatedAt, fetchedSession.CreatedAt, time.Second)

	require.False(t, fetchedSession.IsRevoked)
}
