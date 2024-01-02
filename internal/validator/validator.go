package validator

import (
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

func ValidateWalletAddress(walletAddress string) error {
	if !common.IsHexAddress(walletAddress) {
		return fmt.Errorf("'%s' is not a valid hex address", walletAddress)
	}

	if !strings.HasPrefix(walletAddress, "0x") {
		return fmt.Errorf("'%s' must be prefixed with '0x'", walletAddress)
	}

	zeroAddress := common.HexToAddress("0x0000000000000000000000000000000000000000")
	inputAddress := common.HexToAddress(strings.ToLower(walletAddress))
	if inputAddress == zeroAddress {
		return fmt.Errorf("'%s' must not be a zero address", walletAddress)
	}

	return nil
}

func ValidateChallenge(challenge string, challengePrefix string) error {
	if !strings.HasPrefix(challenge, challengePrefix) {
		return fmt.Errorf("'%s' is invalid", challenge)
	}

	// TODO: Verify that the challenge was issued by the server for the given address.

	return nil
}

func ValidateEthereumSignature(signature string) error {
	signature = strings.TrimPrefix(signature, "0x")
	if len(signature) != 130 {
		return fmt.Errorf("'%s' is invalid", signature)
	}

	return nil
}
