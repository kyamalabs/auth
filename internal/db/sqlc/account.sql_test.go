package db

import (
	"context"
	"testing"

	"github.com/kyamagames/auth/internal/utils"

	"github.com/stretchr/testify/require"
)

func createTestAccount(t *testing.T) (*utils.EthereumWallet, Account) {
	testEthWallet, err := utils.NewEthereumWallet()
	require.NoError(t, err)
	require.NotEmpty(t, testEthWallet)

	account, err := testStore.CreateAccount(context.Background(), testEthWallet.Address)
	require.NoError(t, err)
	require.NotEmpty(t, account)

	require.Equal(t, testEthWallet.Address, account.Owner)

	return testEthWallet, account
}

func TestCreateAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test to maintain db state")
	}

	wallet, account := createTestAccount(t)
	require.NotEmpty(t, wallet)
	require.NotEmpty(t, account)

	require.NotZero(t, account.ID)
	require.NotZero(t, account.CreatedAt)
}
