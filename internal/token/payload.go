package token

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

type Role string

type Access string

var ErrExpiredToken = errors.New("token is expired")

const (
	Gamer Role = "gamer"
	Admin Role = "admin"
)

const (
	AccessToken  Access = "Access Token"
	RefreshToken Access = "Refresh Token"
)

type Payload struct {
	ID            uuid.UUID `json:"id"`
	WalletAddress string    `json:"wallet_address"`
	Role          Role      `json:"role"`
	TokenAccess   Access    `json:"token_access"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

func NewPayload(walletAddress string, role Role, tokenAccess Access, duration time.Duration) (*Payload, error) {
	tokenId, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	payload := &Payload{
		ID:            tokenId,
		WalletAddress: walletAddress,
		Role:          role,
		TokenAccess:   tokenAccess,
		IssuedAt:      time.Now().UTC(),
		ExpiresAt:     time.Now().UTC().Add(duration),
	}

	return payload, nil
}

func (payload *Payload) Valid() error {
	if time.Now().UTC().After(payload.ExpiresAt) {
		return ErrExpiredToken
	}

	return nil
}
