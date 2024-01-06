package validator

import (
	"errors"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

func ValidateWalletAddress(walletAddress string) error {
	if !common.IsHexAddress(walletAddress) {
		return errors.New("not a valid hex address")
	}

	if !strings.HasPrefix(walletAddress, "0x") {
		return errors.New("must be prefixed with '0x'")
	}

	zeroAddress := common.HexToAddress("0x0000000000000000000000000000000000000000")
	inputAddress := common.HexToAddress(strings.ToLower(walletAddress))
	if inputAddress == zeroAddress {
		return errors.New("must not be a zero address")
	}

	return nil
}

func ValidateEthereumSignature(signature string) error {
	signature = strings.TrimPrefix(signature, "0x")
	if len(signature) != 130 {
		return errors.New("not a valid signature")
	}

	return nil
}
