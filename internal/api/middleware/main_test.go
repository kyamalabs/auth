package middleware

import (
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/kyamagames/auth/internal/token"
	"github.com/kyamagames/auth/internal/utils"
	"github.com/stretchr/testify/require"
)

func getTestTokenMaker(t *testing.T) token.Maker {
	config := utils.Config{
		TokenSymmetricKey: gofakeit.LetterN(32),
	}

	tokenMaker, err := token.NewPasetoMaker(config.TokenSymmetricKey)
	require.NoError(t, err)
	require.NotEmpty(t, tokenMaker)

	return tokenMaker
}
