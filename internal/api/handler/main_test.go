package handler

import (
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	db "github.com/kyamagames/auth/internal/db/sqlc"
	"github.com/kyamagames/auth/internal/token"
	"github.com/kyamagames/auth/internal/utils"
	"github.com/stretchr/testify/require"
)

func newTestHandler(t *testing.T, store db.Store) Handler {
	config := utils.Config{
		TokenSymmetricKey: gofakeit.LetterN(32),
	}

	tokenMaker, err := token.NewPasetoMaker(config.TokenSymmetricKey)
	require.NoError(t, err)
	require.NotEmpty(t, tokenMaker)

	return NewHandler(config, store, tokenMaker)
}
