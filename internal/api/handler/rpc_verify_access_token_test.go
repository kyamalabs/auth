package handler

import (
	"context"
	"testing"
	"time"

	"github.com/kyamagames/auth/api/pb"
	mockcache "github.com/kyamagames/auth/internal/cache/mock"
	mockdb "github.com/kyamagames/auth/internal/db/mock"
	"github.com/kyamagames/auth/internal/token"
	"github.com/kyamagames/auth/internal/utils"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func generateTestVerifyAccessTokenReqParams(t *testing.T) *pb.VerifyAccessTokenRequest {
	wallet, err := utils.NewEthereumWallet()
	require.NoError(t, err)
	require.NotEmpty(t, wallet)

	return &pb.VerifyAccessTokenRequest{
		WalletAddress: wallet.Address,
	}
}

func TestVerifyAccessTokenAPI(t *testing.T) {
	verifyAccessTokenReqParams := generateTestVerifyAccessTokenReqParams(t)
	require.NotEmpty(t, verifyAccessTokenReqParams)

	testCases := []struct {
		name          string
		req           *pb.VerifyAccessTokenRequest
		buildContext  func(t *testing.T, tokenMaker token.Maker) context.Context
		checkResponse func(t *testing.T, res *pb.VerifyAccessTokenResponse, err error)
	}{
		{
			name: "Success",
			req:  verifyAccessTokenReqParams,
			buildContext: func(t *testing.T, tokenMaker token.Maker) context.Context {
				return newContextWithBearerToken(t, tokenMaker, verifyAccessTokenReqParams.WalletAddress, token.Gamer, token.AccessToken, 30*time.Second)
			},
			checkResponse: func(t *testing.T, res *pb.VerifyAccessTokenResponse, err error) {
				require.NoError(t, err)
				require.NotEmpty(t, res)
			},
		},
		{
			name: "Failure - invalid request arguments",
			req: &pb.VerifyAccessTokenRequest{
				WalletAddress: verifyAccessTokenReqParams.GetWalletAddress()[:len(verifyAccessTokenReqParams.GetWalletAddress())-1],
			},
			buildContext: func(t *testing.T, tokenMaker token.Maker) context.Context {
				return nil
			},
			checkResponse: func(t *testing.T, res *pb.VerifyAccessTokenResponse, err error) {
				require.Error(t, err)
				require.Empty(t, res)

				expectedFieldViolations := []string{"wallet_address"}
				checkInvalidRequestParams(t, err, expectedFieldViolations)
			},
		},
		{
			name: "Failure - missing authorization header",
			req:  verifyAccessTokenReqParams,
			buildContext: func(t *testing.T, tokenMaker token.Maker) context.Context {
				return context.Background()
			},
			checkResponse: func(t *testing.T, res *pb.VerifyAccessTokenResponse, err error) {
				require.Error(t, err)
				require.Empty(t, res)
				require.ErrorContains(t, err, UnauthorizedAccessError)
			},
		},
	}

	for i := range testCases {
		tc := testCases[i]

		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			store := mockdb.NewMockStore(ctrl)
			cache := mockcache.NewMockCache(ctrl)

			handler := newTestHandler(t, store, cache)

			ctx := tc.buildContext(t, handler.tokenMaker)
			res, err := handler.VerifyAccessToken(ctx, tc.req)
			tc.checkResponse(t, res, err)
		})
	}
}
