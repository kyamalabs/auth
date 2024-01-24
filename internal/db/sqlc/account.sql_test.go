package db

import (
	"context"
	"testing"

	"github.com/kyamagames/auth/pkg/util"

	"github.com/stretchr/testify/require"
)

func createTestAccount(t *testing.T) (*util.EthereumWallet, Account) {
	testEthWallet, err := util.NewEthereumWallet()
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

func TestGetAccountByOwner(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test to maintain db state")
	}

	wallet, account := createTestAccount(t)
	require.NotEmpty(t, wallet)
	require.NotEmpty(t, account)

	testCases := []struct {
		name           string
		owner          string
		isAccountFound bool
	}{
		{
			name:           "Success",
			owner:          account.Owner,
			isAccountFound: true,
		},
		{
			name:           "Fail: invalid account owner",
			owner:          "0x0000000000000000000000000000000000000000",
			isAccountFound: false,
		},
	}

	for i := range testCases {
		tc := testCases[i]

		t.Run(tc.name, func(t *testing.T) {
			fetchedAccount, err := testStore.GetAccountByOwner(context.Background(), tc.owner)

			if tc.isAccountFound {
				require.NoError(t, err)
				require.NotEmpty(t, fetchedAccount)
				require.Equal(t, account, fetchedAccount)
			} else {
				require.Equal(t, RecordNotFoundError, err)
				require.Equal(t, Account{}, fetchedAccount)
			}
		})
	}
}
