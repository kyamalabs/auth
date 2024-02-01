package validator

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateWalletAddress(t *testing.T) {
	testCases := []struct {
		name            string
		walletAddress   string
		expectedToError bool
	}{
		{
			name:            "no error",
			walletAddress:   "0x999999cf1046e68e36E1aA2E0E07105eDDD1f08E",
			expectedToError: false,
		},
		{
			name:            "not a valid hex address",
			walletAddress:   "0x999999cf1046e68e36E1aA2E0E07105eDDD1f08",
			expectedToError: true,
		},
		{
			name:            "not prefixed with 0x",
			walletAddress:   "999999cf1046e68e36E1aA2E0E07105eDDD1f08E",
			expectedToError: true,
		},
		{
			name:            "is a zero address",
			walletAddress:   "0x0000000000000000000000000000000000000000",
			expectedToError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateWalletAddress(tc.walletAddress)
			if tc.expectedToError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestValidateEthereumSignature(t *testing.T) {
	testCases := []struct {
		name            string
		signature       string
		expectedToError bool
	}{
		{
			name:            "invalid length with prefix",
			signature:       "0x71c9248cb5ef3920f5bfc47164f3605f023076b769df518a7e005f1222122b023199175bfb6d5829faa5b88c1490ea93cbb1b2857b533748526a3abcbabca71b",
			expectedToError: true,
		},
		{
			name:            "invalid length without prefix",
			signature:       "791c9248cb5ef3920f5bfc47164f3605f023076b769df518a7e005f1222122b023199175bfb6d5829faa5b88c1490ea93cbb1b2857b533748526a3abcbabca71b",
			expectedToError: true,
		},
		{
			name:            "valid length without prefix",
			signature:       "7912c9248cb5ef3920f5bfc47164f3605f023076b769df518a7e005f1222122b023199175bfb6d5829faa5b88c1490ea93cbb1b2857b533748526a3abcbabca71b",
			expectedToError: false,
		},
		{
			name:            "valid length with prefix",
			signature:       "0x791c9248cb5ef3920f5bfc47164f3605f023076b769dfk518a7e005f1222122b023199175bfb6d5829faa5b88c1490ea93cbb1b2857b533748526a3abcbabca71b",
			expectedToError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateEthereumSignature(tc.signature)
			if tc.expectedToError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
		})
	}
}
