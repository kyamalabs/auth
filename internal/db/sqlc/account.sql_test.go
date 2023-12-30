package db

import (
	"context"
	"testing"

	"github.com/kyamagames/auth/internal/utils"

	"github.com/stretchr/testify/require"
)

func createTestAccount(t *testing.T) Account {
	testEthWallet := utils.NewEthereumWallet()

	account, err := testStore.CreateAccount(context.Background(), testEthWallet.Address)
	require.NoError(t, err)
	require.NotEmpty(t, account)

	require.Equal(t, testEthWallet.Address, account.Owner)

	return account
}

func TestCreateAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test to maintain db state")
	}

	account := createTestAccount(t)
	require.NotEmpty(t, account)

	require.NotZero(t, account.ID)
	require.NotZero(t, account.CreatedAt)
}
