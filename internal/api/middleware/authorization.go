package middleware

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/kyamagames/auth/internal/token"
	"google.golang.org/grpc/metadata"
)

func AuthorizeAccount(ctx context.Context, walletAddress string, tokenMaker token.Maker, tokenAccess token.Access, accessibleRoles []token.Role) (*token.Payload, error) {
	mtdt, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.New("could not get metadata from incoming context")
	}

	authValues := mtdt.Get(AuthorizationHeader)
	if len(authValues) == 0 {
		return nil, errors.New("missing authorization header")
	}

	authHeader := authValues[0]
	fields := strings.Fields(authHeader)
	if len(fields) < 2 {
		return nil, errors.New("invalid authorization header format")
	}

	authType := fields[0]
	if !strings.EqualFold(AuthorizationBearer, authType) {
		return nil, fmt.Errorf("unsupported authorization type: %s", authType)
	}

	tk := fields[1]
	payload, err := tokenMaker.VerifyToken(tk)
	if err != nil {
		return nil, fmt.Errorf("invalid authorization token: %s", err)
	}

	if payload.TokenAccess != tokenAccess {
		return nil, fmt.Errorf("unauthorized token access: %s", payload.TokenAccess)
	}

	if !hasPermission(payload.Role, accessibleRoles) {
		return nil, fmt.Errorf("permission denied: attempting to use inaccessible role: '%s'", payload.Role)
	}

	if payload.Role == token.Gamer && walletAddress != payload.WalletAddress {
		return nil, errors.New("permission denied: attempting to use another account's credentials")
	}

	return payload, nil
}

func hasPermission(role token.Role, accessibleRoles []token.Role) bool {
	for _, r := range accessibleRoles {
		if r == role {
			return true
		}
	}
	return false
}
