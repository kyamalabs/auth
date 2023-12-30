package token

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kyamagames/auth/internal/utils"
	"github.com/stretchr/testify/require"
)

func createNewPayload(t *testing.T, duration time.Duration) *Payload {
	ethereumWallet, err := utils.NewEthereumWallet()
	require.NoError(t, err)
	require.NotEmpty(t, ethereumWallet)

	payload, err := NewPayload(ethereumWallet.Address, Gamer, duration)
	require.NoError(t, err)
	require.NotEmpty(t, payload)

	require.NotEmpty(t, payload.ID)
	require.IsType(t, uuid.UUID{}, payload.ID)
	require.Equal(t, ethereumWallet.Address, payload.WalletAddress)
	require.Equal(t, Gamer, payload.Role)
	require.WithinDuration(t, time.Now().UTC(), payload.IssuedAt, time.Second)
	require.WithinDuration(t, time.Now().UTC().Add(duration), payload.ExpiredAt, time.Second)

	return payload
}

func TestNewPayload(t *testing.T) {
	createNewPayload(t, 5*time.Hour)
}

func TestPayload_Valid(t *testing.T) {
	testCases := []struct {
		name            string
		duration        time.Duration
		isTokenValidErr error
	}{
		{
			name:            "Valid token",
			duration:        2 * time.Minute,
			isTokenValidErr: nil,
		},
		{
			name:            "Expired token",
			duration:        -1 * 5 * time.Hour,
			isTokenValidErr: ErrExpiredToken,
		},
	}

	for i := range testCases {
		tc := testCases[i]

		t.Run(tc.name, func(t *testing.T) {
			payload := createNewPayload(t, tc.duration)
			isPayloadValidErr := payload.Valid()

			require.Equal(t, tc.isTokenValidErr, isPayloadValidErr)
		})
	}
}
