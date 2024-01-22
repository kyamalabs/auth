package handler

import (
	"context"
	"fmt"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/status"

	"github.com/kyamagames/auth/internal/api/middleware"
	"google.golang.org/grpc/metadata"

	"github.com/kyamagames/auth/internal/cache"

	"github.com/brianvoe/gofakeit/v6"
	db "github.com/kyamagames/auth/internal/db/sqlc"
	"github.com/kyamagames/auth/internal/token"
	"github.com/kyamagames/auth/internal/util"
	"github.com/stretchr/testify/require"
)

func newTestHandler(t *testing.T, store db.Store, cache cache.Cache) Handler {
	config := util.Config{
		TokenSymmetricKey: gofakeit.LetterN(32),
	}

	tokenMaker, err := token.NewPasetoMaker(config.TokenSymmetricKey)
	require.NoError(t, err)
	require.NotEmpty(t, tokenMaker)

	return NewHandler(config, store, tokenMaker, cache)
}

func newContextWithBearerToken(t *testing.T, tokenMaker token.Maker, accountOwner string, role token.Role, tokenAccess token.Access, duration time.Duration) context.Context {
	tk, _, err := tokenMaker.CreateToken(accountOwner, role, tokenAccess, duration)
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

func checkInvalidRequestParams(t *testing.T, err error, expectedFieldViolations []string) {
	var violations []string

	st, ok := status.FromError(err)
	require.True(t, ok)

	details := st.Details()

	for _, detail := range details {
		br, ok := detail.(*errdetails.BadRequest)
		require.True(t, ok)

		fieldViolations := br.FieldViolations
		for _, violation := range fieldViolations {
			violations = append(violations, violation.Field)
		}
	}

	require.ElementsMatch(t, expectedFieldViolations, violations)
}
