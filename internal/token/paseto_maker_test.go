package token

import (
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/kyamagames/auth/internal/utils"
	"github.com/stretchr/testify/require"
)

func createPasetoToken(t *testing.T, tokenAccess TokenAccess, duration time.Duration) (*utils.EthereumWallet, Maker, string) {
	ethereumWallet, err := utils.NewEthereumWallet()
	require.NoError(t, err)
	require.NotEmpty(t, ethereumWallet)

	maker, err := NewPasetoMaker(gofakeit.LetterN(32))
	require.NoError(t, err)
	require.NotEmpty(t, maker)

	token, payload, err := maker.CreateToken(ethereumWallet.Address, Gamer, tokenAccess, duration)
	require.NoError(t, err)
	require.NotEmpty(t, payload)

	require.NotEmpty(t, token)

	return ethereumWallet, maker, token
}

func TestNewPasetoMaker(t *testing.T) {
	testCases := []struct {
		name         string
		symmetricKey string
		isSuccess    bool
	}{
		{
			name:         "Success",
			symmetricKey: gofakeit.LetterN(32),
			isSuccess:    true,
		},
		{
			name:         "Invalid key size",
			symmetricKey: "invalid_symmetric_key",
			isSuccess:    false,
		},
	}

	for i := range testCases {
		tc := testCases[i]

		t.Run(tc.name, func(t *testing.T) {
			maker, err := NewPasetoMaker(tc.symmetricKey)
			if tc.isSuccess {
				require.NoError(t, err)
				require.NotEmpty(t, maker)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestPasetoMaker_CreateToken(t *testing.T) {
	createPasetoToken(t, AccessToken, 5*time.Hour)
}

func TestPasetoMaker_VerifyToken(t *testing.T) {
	duration := 5 * time.Hour
	wallet, maker, token := createPasetoToken(t, AccessToken, duration)

	testCases := []struct {
		name      string
		token     string
		isSuccess bool
	}{
		{
			name:      "Success",
			token:     token,
			isSuccess: true,
		},
		{
			name:      "Invalid token",
			token:     "invalid_token",
			isSuccess: false,
		},
	}

	for i := range testCases {
		tc := testCases[i]

		t.Run(tc.name, func(t *testing.T) {
			require.NotEmpty(t, maker)
			require.NotEmpty(t, tc.token)

			payload, err := maker.VerifyToken(tc.token)
			if tc.isSuccess {
				require.NoError(t, err)
				require.NotEmpty(t, payload)
			} else {
				require.Error(t, err)
				require.Nil(t, payload)
				return
			}

			require.NotEmpty(t, payload.ID)
			require.IsType(t, uuid.UUID{}, payload.ID)
			require.Equal(t, wallet.Address, payload.WalletAddress)
			require.Equal(t, Gamer, payload.Role)
			require.WithinDuration(t, time.Now().UTC(), payload.IssuedAt, time.Second)
			require.WithinDuration(t, time.Now().UTC().Add(duration), payload.ExpiresAt, time.Second)
		})
	}
}
