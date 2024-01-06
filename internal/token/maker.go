package token

import "time"

type Maker interface {
	CreateToken(walletAddress string, role Role, tokenAccess TokenAccess, duration time.Duration) (string, *Payload, error)
	VerifyToken(token string) (*Payload, error)
}
