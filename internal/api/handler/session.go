package handler

import (
	"context"
	"fmt"
	"time"

	"github.com/kyamagames/auth/internal/api/middleware"

	db "github.com/kyamagames/auth/internal/db/sqlc"
	"github.com/kyamagames/auth/internal/token"
	"github.com/kyamagames/auth/internal/utils"
)

type Session struct {
	ID                  string
	AccessToken         string
	AccessTokenPayload  *token.Payload
	RefreshToken        string
	RefreshTokenPayload *token.Payload
	ExpiresAt           time.Time
}

func NewSession(ctx context.Context, accountOwner string, accountRole token.Role, config utils.Config, tokenMaker token.Maker, store db.Store) (*Session, error) {
	accessToken, accessTokenPayload, err := tokenMaker.CreateToken(accountOwner, accountRole, config.AccessTokenDuration)
	if err != nil {
		return nil, fmt.Errorf("could not create access token: %w", err)
	}

	refreshToken, refreshTokenPayload, err := tokenMaker.CreateToken(accountOwner, accountRole, config.RefreshTokenDuration)
	if err != nil {
		return nil, fmt.Errorf("could not create refresh token token: %w", err)
	}

	metadata := middleware.ExtractMetadata(ctx)

	session, err := store.CreateSession(ctx, db.CreateSessionParams{
		ID:            refreshTokenPayload.ID,
		WalletAddress: accountOwner,
		RefreshToken:  refreshToken,
		UserAgent:     metadata.UserAgent,
		ClientIp:      metadata.ClientIP,
		ExpiresAt:     refreshTokenPayload.ExpiresAt,
	})
	if err != nil {
		return nil, fmt.Errorf("could not create db session: %w", err)
	}

	return &Session{
		ID:                  session.ID.String(),
		AccessToken:         accessToken,
		AccessTokenPayload:  accessTokenPayload,
		RefreshToken:        refreshToken,
		RefreshTokenPayload: refreshTokenPayload,
		ExpiresAt:           refreshTokenPayload.ExpiresAt,
	}, nil
}
