package handler

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kyamagames/auth/internal/api/middleware"
	"google.golang.org/grpc/metadata"

	"github.com/kyamagames/auth/internal/cache"

	"github.com/brianvoe/gofakeit/v6"
	db "github.com/kyamagames/auth/internal/db/sqlc"
	"github.com/kyamagames/auth/internal/token"
	"github.com/kyamagames/auth/internal/utils"
	"github.com/stretchr/testify/require"
)

func newTestHandler(t *testing.T, store db.Store, cache cache.Cache) Handler {
	config := utils.Config{
		TokenSymmetricKey: gofakeit.LetterN(32),
	}

	tokenMaker, err := token.NewPasetoMaker(config.TokenSymmetricKey)
	require.NoError(t, err)
	require.NotEmpty(t, tokenMaker)

	return NewHandler(config, store, tokenMaker, cache)
}

func newContextWithBearerToken(t *testing.T, tokenMaker token.Maker, accountOwner string, role token.Role, duration time.Duration) context.Context {
	tk, _, err := tokenMaker.CreateToken(accountOwner, role, duration)
	require.NoError(t, err)
	require.NotEmpty(t, tk)

	bearerToken := fmt.Sprintf("%s %s", middleware.AuthorizationBearer, tk)
	md := metadata.MD{
		middleware.AuthorizationHeader: []string{
			bearerToken,
		},
	}

	return metadata.NewIncomingContext(context.Background(), md)
}
