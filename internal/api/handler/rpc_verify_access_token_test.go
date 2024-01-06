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
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/status"
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
				return newContextWithBearerToken(t, tokenMaker, verifyAccessTokenReqParams.WalletAddress, token.Gamer, 30*time.Second)
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

				var violations []string
				expectedFieldViolations := []string{"wallet_address"}

				st, ok := status.FromError(err)
				require.True(t, ok)
				details := st.Details()
				for _, detail := range details {
					br, ok := detail.(*errdetails.BadRequest)
					require.True(t, ok)
					fieldViolations := br.FieldViolations
					for _, violation := range fieldViolations {
						violations = append(violations, violation.Field)
					}
				}

				require.ElementsMatch(t, expectedFieldViolations, violations)
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
