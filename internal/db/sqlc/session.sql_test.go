package db

import (
	"context"
	"crypto/rand"
	"math/big"
	"testing"
	"time"

	"github.com/kyamagames/auth/internal/token"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func createTestSession(t *testing.T, walletAddress string) Session {
	maker, err := token.NewPasetoMaker(gofakeit.LetterN(32))
	require.NoError(t, err)
	require.NotEmpty(t, maker)

	refreshToken, payload, err := maker.CreateToken(walletAddress, token.Gamer, 1*time.Hour)
	require.NoError(t, err)
	require.NotEmpty(t, payload)
	require.NotEmpty(t, refreshToken)

	randomNum, err := rand.Int(rand.Reader, big.NewInt(2))
	require.NoError(t, err)

	// set client IP to either IPv4 or IPv6
	clientIP := gofakeit.IPv4Address()
	if randomNum.Int64() == 1 {
		clientIP = gofakeit.IPv6Address()
	}

	params := CreateSessionParams{
		ID:            uuid.New(),
		WalletAddress: walletAddress,
		RefreshToken:  refreshToken,
		UserAgent:     gofakeit.UserAgent(),
		ClientIp:      clientIP,
		ExpiresAt:     time.Now().UTC().Add(3 * time.Hour),
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

	require.Equal(t, walletAddress, session.WalletAddress)

	require.False(t, session.IsRevoked)

	return session
}

func TestCreateSession(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test to maintain db state")
	}

	wallet, account := createTestAccount(t)
	require.NotEmpty(t, wallet)
	require.NotEmpty(t, account)

	session := createTestSession(t, wallet.Address)
	require.NotEmpty(t, session)
}

func TestGetSession(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test to maintain db state")
	}

	wallet, account := createTestAccount(t)
	require.NotEmpty(t, wallet)
	require.NotEmpty(t, account)

	session := createTestSession(t, wallet.Address)
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

func TestRevokeAccountSessions(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test to maintain db state")
	}

	wallet, account := createTestAccount(t)
	require.NotEmpty(t, wallet)
	require.NotEmpty(t, account)

	numCreatedSessions := 12
	var createdSessions []Session

	for i := 0; i < numCreatedSessions; i++ {
		session := createTestSession(t, wallet.Address)
		require.NotEmpty(t, session)

		createdSessions = append(createdSessions, session)
	}

	ct, err := testStore.RevokeAccountSessions(context.Background(), wallet.Address)
	require.NoError(t, err)
	require.Equal(t, numCreatedSessions, int(ct.RowsAffected()))

	for _, createdSession := range createdSessions {
		gotSession, err := testStore.GetSession(context.Background(), createdSession.ID)
		require.NoError(t, err)
		require.NotEmpty(t, gotSession)
		require.True(t, gotSession.IsRevoked)
	}
}
