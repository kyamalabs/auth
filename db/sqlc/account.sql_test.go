// +build ci

package db

import (
	"context"
	"testing"

	"github.com/kyamagames/auth/utils"

	"github.com/stretchr/testify/require"
)

func TestCreateAccount(t *testing.T) {
	testEthWallet := utils.NewEthereumWallet()
	account, err := testStore.CreateAccount(context.Background(), testEthWallet.Address)

	require.NoError(t, err)
	require.NotEmpty(t, account)

	require.Equal(t, testEthWallet.Address, account.Owner)
	require.NotZero(t, account.ID)
	require.NotZero(t, account.CreatedAt)
}
