package utils

import (
	"crypto/ecdsa"
	"log"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"
)

type EthereumWallet struct {
	PublicKey     string `json:"public_key"`
	PrivateKey    string `json:"private_key"`
	Address       string `json:"address"`
	PublicKeyHash string `json:"hash"`
}

func NewEthereumWallet() (ethereumWallet EthereumWallet) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	privateKeyBytes := crypto.FromECDSA(privateKey)
	ethereumWallet.PrivateKey = hexutil.Encode(privateKeyBytes)[2:]

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("error casting public key to ECDSA")
	}

	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	ethereumWallet.PublicKey = hexutil.Encode(publicKeyBytes)[4:]

	ethereumWallet.Address = crypto.PubkeyToAddress(*publicKeyECDSA).Hex()

	hash := sha3.NewLegacyKeccak256()
	hash.Write(publicKeyBytes[1:])
	ethereumWallet.PublicKeyHash = hexutil.Encode(hash.Sum(nil)[12:])

	return
}
