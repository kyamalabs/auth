package token

import "time"

type Maker interface {
	CreateToken(walletAddress string, role Role, tokenAccess Access, duration time.Duration) (string, *Payload, error)
	VerifyToken(token string) (*Payload, error)
}
