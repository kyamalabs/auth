package middleware

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kyamalabs/auth/internal/token"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

func TestAuthorizeAccount(t *testing.T) {
	testWalletAddress := "0x37E0D2456f58fDe5bfe56B0790591b3b8181c42E"

	testCases := []struct {
		name            string
		buildContext    func(t *testing.T, tokenMaker token.Maker) context.Context
		walletAddress   string
		tokenAccess     token.Access
		accessibleRoles []token.Role
		checkResponse   func(t *testing.T, payload *token.Payload, err error)
	}{
		{
			name: "Success",
			buildContext: func(t *testing.T, tokenMaker token.Maker) context.Context {
				tk, _, err := tokenMaker.CreateToken(testWalletAddress, token.Gamer, token.AccessToken, 30*time.Second)
				require.NoError(t, err)
				require.NotEmpty(t, tk)

				bearerToken := fmt.Sprintf("%s %s", AuthorizationBearer, tk)
				md := metadata.MD{
					AuthorizationHeader: []string{
						bearerToken,
					},
				}

				return metadata.NewIncomingContext(context.Background(), md)
			},
			walletAddress:   testWalletAddress,
			tokenAccess:     token.AccessToken,
			accessibleRoles: []token.Role{token.Gamer},
			checkResponse: func(t *testing.T, payload *token.Payload, err error) {
				require.NoError(t, err)
				require.NotEmpty(t, payload)

				require.Equal(t, testWalletAddress, payload.WalletAddress)
				require.Equal(t, token.Gamer, payload.Role)
			},
		},
		{
			name: "Failure - missing metadata from incoming context",
			buildContext: func(t *testing.T, tokenMaker token.Maker) context.Context {
				return context.Background()
			},
			walletAddress:   testWalletAddress,
			tokenAccess:     token.AccessToken,
			accessibleRoles: []token.Role{token.Gamer},
			checkResponse: func(t *testing.T, payload *token.Payload, err error) {
				require.Error(t, err)
				require.Empty(t, payload)
			},
		},
		{
			name: "Failure - missing authorization header",
			buildContext: func(t *testing.T, tokenMaker token.Maker) context.Context {
				md := metadata.MD{
					"some_other_header": []string{
						"some_value",
					},
				}

				return metadata.NewIncomingContext(context.Background(), md)
			},
			walletAddress:   testWalletAddress,
			tokenAccess:     token.AccessToken,
			accessibleRoles: []token.Role{token.Gamer},
			checkResponse: func(t *testing.T, payload *token.Payload, err error) {
				require.Error(t, err)
				require.Empty(t, payload)
			},
		},
		{
			name: "Failure - invalid authorization header format",
			buildContext: func(t *testing.T, tokenMaker token.Maker) context.Context {
				md := metadata.MD{
					AuthorizationHeader: []string{
						"some_value",
					},
				}

				return metadata.NewIncomingContext(context.Background(), md)
			},
			walletAddress:   testWalletAddress,
			tokenAccess:     token.AccessToken,
			accessibleRoles: []token.Role{token.Gamer},
			checkResponse: func(t *testing.T, payload *token.Payload, err error) {
				require.Error(t, err)
				require.Empty(t, payload)
			},
		},
		{
			name: "Failure - unsupported authorization type",
			buildContext: func(t *testing.T, tokenMaker token.Maker) context.Context {
				md := metadata.MD{
					AuthorizationHeader: []string{
						fmt.Sprintf("%s %s", "unsupported_auth_type", "some_token"),
					},
				}

				return metadata.NewIncomingContext(context.Background(), md)
			},
			walletAddress:   testWalletAddress,
			tokenAccess:     token.AccessToken,
			accessibleRoles: []token.Role{token.Gamer},
			checkResponse: func(t *testing.T, payload *token.Payload, err error) {
				require.Error(t, err)
				require.Empty(t, payload)
			},
		},
		{
			name: "Failure - invalid authorization token",
			buildContext: func(t *testing.T, tokenMaker token.Maker) context.Context {
				tk, _, err := tokenMaker.CreateToken(testWalletAddress, token.Gamer, token.AccessToken, -30*time.Second)
				require.NoError(t, err)

				md := metadata.MD{
					AuthorizationHeader: []string{
						fmt.Sprintf("%s %s", AuthorizationBearer, tk),
					},
				}

				return metadata.NewIncomingContext(context.Background(), md)
			},
			walletAddress:   testWalletAddress,
			tokenAccess:     token.AccessToken,
			accessibleRoles: []token.Role{token.Gamer},
			checkResponse: func(t *testing.T, payload *token.Payload, err error) {
				require.Error(t, err)
				require.Empty(t, payload)
			},
		},
		{
			name: "Failure - inaccessible role",
			buildContext: func(t *testing.T, tokenMaker token.Maker) context.Context {
				tk, _, err := tokenMaker.CreateToken(testWalletAddress, token.Admin, token.AccessToken, 30*time.Second)
				require.NoError(t, err)

				md := metadata.MD{
					AuthorizationHeader: []string{
						fmt.Sprintf("%s %s", AuthorizationBearer, tk),
					},
				}

				return metadata.NewIncomingContext(context.Background(), md)
			},
			walletAddress:   testWalletAddress,
			tokenAccess:     token.AccessToken,
			accessibleRoles: []token.Role{token.Gamer},
			checkResponse: func(t *testing.T, payload *token.Payload, err error) {
				require.Error(t, err)
				require.Empty(t, payload)
			},
		},
		{
			name: "Failure - mismatch in wallet addresses for gamer role",
			buildContext: func(t *testing.T, tokenMaker token.Maker) context.Context {
				tk, _, err := tokenMaker.CreateToken(testWalletAddress, token.Gamer, token.AccessToken, 30*time.Second)
				require.NoError(t, err)

				md := metadata.MD{
					AuthorizationHeader: []string{
						fmt.Sprintf("%s %s", AuthorizationBearer, tk),
					},
				}

				return metadata.NewIncomingContext(context.Background(), md)
			},
			walletAddress:   "some_other_wallet_address",
			tokenAccess:     token.AccessToken,
			accessibleRoles: []token.Role{token.Gamer},
			checkResponse: func(t *testing.T, payload *token.Payload, err error) {
				require.Error(t, err)
				require.Empty(t, payload)
			},
		},
		{
			name: "mismatch in token access",
			buildContext: func(t *testing.T, tokenMaker token.Maker) context.Context {
				tk, _, err := tokenMaker.CreateToken(testWalletAddress, token.Gamer, token.AccessToken, 30*time.Second)
				require.NoError(t, err)

				md := metadata.MD{
					AuthorizationHeader: []string{
						fmt.Sprintf("%s %s", AuthorizationBearer, tk),
					},
				}

				return metadata.NewIncomingContext(context.Background(), md)
			},
			walletAddress:   "some_other_wallet_address",
			tokenAccess:     token.RefreshToken,
			accessibleRoles: []token.Role{token.Gamer},
			checkResponse: func(t *testing.T, payload *token.Payload, err error) {
				require.Error(t, err)
				require.Empty(t, payload)
			},
		},
	}

	for i := range testCases {
		tc := testCases[i]

		t.Run(tc.name, func(t *testing.T) {
			tokenMaker := getTestTokenMaker(t)

			ctx := tc.buildContext(t, tokenMaker)
			payload, err := AuthorizeAccount(ctx, tc.walletAddress, tokenMaker, tc.tokenAccess, tc.accessibleRoles)

			tc.checkResponse(t, payload, err)
		})
	}
}
