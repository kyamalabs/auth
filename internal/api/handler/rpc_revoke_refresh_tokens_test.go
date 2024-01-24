package handler

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/kyamagames/auth/pkg/util"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/kyamagames/auth/api/pb"
	mockcache "github.com/kyamagames/auth/internal/cache/mock"
	mockdb "github.com/kyamagames/auth/internal/db/mock"
	"github.com/kyamagames/auth/internal/token"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func generateTestRevokeRefreshTokensReqParams(t *testing.T) *pb.RevokeRefreshTokensRequest {
	wallet, err := util.NewEthereumWallet()
	require.NoError(t, err)
	require.NotEmpty(t, wallet)

	return &pb.RevokeRefreshTokensRequest{
		WalletAddress: wallet.Address,
	}
}

func TestRevokeRefreshTokensAPI(t *testing.T) {
	revokeRefreshTokensReqParams := generateTestRevokeRefreshTokensReqParams(t)
	require.NotEmpty(t, revokeRefreshTokensReqParams)

	testCases := []struct {
		name          string
		req           *pb.RevokeRefreshTokensRequest
		buildStubs    func(store *mockdb.MockStore, cache *mockcache.MockCache)
		buildContext  func(t *testing.T, tokenMaker token.Maker) context.Context
		checkResponse func(t *testing.T, res *pb.RevokeRefreshTokensResponse, err error)
	}{
		{
			name: "success",
			req:  revokeRefreshTokensReqParams,
			buildStubs: func(store *mockdb.MockStore, cache *mockcache.MockCache) {
				testCt := pgconn.NewCommandTag(fmt.Sprintf("test %d", int64(2)))

				store.EXPECT().
					RevokeAccountSessions(gomock.Any(), revokeRefreshTokensReqParams.WalletAddress).
					Times(1).
					Return(testCt, nil)
			},
			buildContext: func(t *testing.T, tokenMaker token.Maker) context.Context {
				return newContextWithBearerToken(t, tokenMaker, revokeRefreshTokensReqParams.WalletAddress, token.Gamer, token.AccessToken, 30*time.Second)
			},
			checkResponse: func(t *testing.T, res *pb.RevokeRefreshTokensResponse, err error) {
				require.NoError(t, err)
				require.NotEmpty(t, res)
				require.Equal(t, int64(2), res.NumSessionsRevoked)
			},
		},
		{
			name: "invalid request parameters",
			req: &pb.RevokeRefreshTokensRequest{
				WalletAddress: "0x00",
			},
			buildStubs: func(store *mockdb.MockStore, cache *mockcache.MockCache) {
			},
			buildContext: func(t *testing.T, tokenMaker token.Maker) context.Context {
				return context.Background()
			},
			checkResponse: func(t *testing.T, res *pb.RevokeRefreshTokensResponse, err error) {
				require.Error(t, err)
				require.Empty(t, res)

				expectedFieldViolations := []string{"wallet_address"}
				checkInvalidRequestParams(t, err, expectedFieldViolations)
			},
		},
		{
			name: "unauthorized access",
			req:  revokeRefreshTokensReqParams,
			buildStubs: func(store *mockdb.MockStore, cache *mockcache.MockCache) {
			},
			buildContext: func(t *testing.T, tokenMaker token.Maker) context.Context {
				return newContextWithBearerToken(t, tokenMaker, revokeRefreshTokensReqParams.WalletAddress, token.Gamer, token.RefreshToken, 30*time.Second)
			},
			checkResponse: func(t *testing.T, res *pb.RevokeRefreshTokensResponse, err error) {
				require.Error(t, err)
				require.Empty(t, res)
				require.ErrorContains(t, err, UnauthorizedAccessError)
			},
		},
		{
			name: "could not revoke refresh tokens",
			req:  revokeRefreshTokensReqParams,
			buildStubs: func(store *mockdb.MockStore, cache *mockcache.MockCache) {
				store.EXPECT().
					RevokeAccountSessions(gomock.Any(), revokeRefreshTokensReqParams.WalletAddress).
					Times(1).
					Return(pgconn.CommandTag{}, errors.New("some db error"))
			},
			buildContext: func(t *testing.T, tokenMaker token.Maker) context.Context {
				return newContextWithBearerToken(t, tokenMaker, revokeRefreshTokensReqParams.WalletAddress, token.Gamer, token.AccessToken, 30*time.Second)
			},
			checkResponse: func(t *testing.T, res *pb.RevokeRefreshTokensResponse, err error) {
				require.Error(t, err)
				require.Empty(t, res)
				require.ErrorContains(t, err, InternalServerError)
			},
		},
		{
			name: "has admin access",
			req:  revokeRefreshTokensReqParams,
			buildStubs: func(store *mockdb.MockStore, cache *mockcache.MockCache) {
				testCt := pgconn.NewCommandTag(fmt.Sprintf("test %d", int64(2)))

				store.EXPECT().
					RevokeAccountSessions(gomock.Any(), revokeRefreshTokensReqParams.WalletAddress).
					Times(1).
					Return(testCt, nil)
			},
			buildContext: func(t *testing.T, tokenMaker token.Maker) context.Context {
				wallet, err := util.NewEthereumWallet()
				require.NoError(t, err)
				require.NotEmpty(t, wallet)

				return newContextWithBearerToken(t, tokenMaker, wallet.Address, token.Admin, token.AccessToken, 30*time.Second)
			},
			checkResponse: func(t *testing.T, res *pb.RevokeRefreshTokensResponse, err error) {
				require.NoError(t, err)
				require.NotEmpty(t, res)
				require.Equal(t, int64(2), res.NumSessionsRevoked)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			store := mockdb.NewMockStore(ctrl)
			cache := mockcache.NewMockCache(ctrl)

			handler := newTestHandler(t, store, cache)

			tc.buildStubs(store, cache)

			ctx := tc.buildContext(t, handler.tokenMaker)
			res, err := handler.RevokeRefreshTokens(ctx, tc.req)
			tc.checkResponse(t, res, err)
		})
	}
}
