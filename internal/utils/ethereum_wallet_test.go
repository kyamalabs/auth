package utils

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func derivePublicKeyFromPrivateKey(privateKeyHex string) (string, error) {
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", err
	}

	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return "", err
	}

	publicKeyBytes := append(privateKey.X.Bytes(), privateKey.Y.Bytes()...)
	uncompressedPublicKeyHex := hex.EncodeToString(publicKeyBytes)

	return uncompressedPublicKeyHex, nil
}

func TestNewEthereumWallet(t *testing.T) {
	testEthereumWallet, err := NewEthereumWallet()
	require.NoError(t, err)
	require.NotEmpty(t, testEthereumWallet)

	require.Equal(t, strings.ToLower(testEthereumWallet.PublicKeyHash), strings.ToLower(testEthereumWallet.Address))

	derivedPublicKey, err := derivePublicKeyFromPrivateKey(testEthereumWallet.PrivateKey)
	require.NoError(t, err)
	require.Equal(t, derivedPublicKey, testEthereumWallet.PublicKey)
}
