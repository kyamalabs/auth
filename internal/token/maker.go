package token

import "time"

type Maker interface {
	CreateToken(walletAddress string, role Role, duration time.Duration) (string, *Payload, error)
	VerifyToken(token string) (*Payload, error)
}
