package handler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kyamagames/auth/pkg/util"

	"github.com/google/uuid"
	"github.com/kyamagames/auth/api/pb"
	mockcache "github.com/kyamagames/auth/internal/cache/mock"
	mockdb "github.com/kyamagames/auth/internal/db/mock"
	db "github.com/kyamagames/auth/internal/db/sqlc"
	"github.com/kyamagames/auth/internal/token"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func generateTestRefreshAccessTokenReqParams(t *testing.T) *pb.RefreshAccessTokenRequest {
	wallet, err := util.NewEthereumWallet()
	require.NoError(t, err)
	require.NotEmpty(t, wallet)

	return &pb.RefreshAccessTokenRequest{
		WalletAddress: wallet.Address,
	}
}

func TestRefreshAccessTokenAPI(t *testing.T) {
	refreshAccessTokenReqParams := generateTestRefreshAccessTokenReqParams(t)
	require.NotEmpty(t, refreshAccessTokenReqParams)

	testCases := []struct {
		name          string
		req           *pb.RefreshAccessTokenRequest
		buildStubs    func(store *mockdb.MockStore, cache *mockcache.MockCache)
		buildContext  func(t *testing.T, tokenMaker token.Maker) context.Context
		checkResponse func(t *testing.T, res *pb.RefreshAccessTokenResponse, err error)
	}{
		{
			name: "success",
			req:  refreshAccessTokenReqParams,
			buildStubs: func(store *mockdb.MockStore, cache *mockcache.MockCache) {
				store.EXPECT().
					GetSession(gomock.Any(), gomock.Any()).
					Times(1).
					Return(db.Session{
						ID:           uuid.New(),
						IsRevoked:    false,
						RefreshToken: "refresh_token",
						ExpiresAt:    time.Now().UTC().Add(1 * time.Minute),
					}, nil)
			},
			buildContext: func(t *testing.T, tokenMaker token.Maker) context.Context {
				return newContextWithBearerToken(t, tokenMaker, refreshAccessTokenReqParams.WalletAddress, token.Gamer, token.RefreshToken, 30*time.Second)
			},
			checkResponse: func(t *testing.T, res *pb.RefreshAccessTokenResponse, err error) {
				require.NoError(t, err)
				require.NotEmpty(t, res)
			},
		},
		{
			name: "invalid request params",
			req: &pb.RefreshAccessTokenRequest{
				WalletAddress: "0x",
			},
			buildStubs: func(store *mockdb.MockStore, cache *mockcache.MockCache) {
			},
			buildContext: func(t *testing.T, tokenMaker token.Maker) context.Context {
				return context.Background()
			},
			checkResponse: func(t *testing.T, res *pb.RefreshAccessTokenResponse, err error) {
				require.Error(t, err)
				require.Empty(t, res)

				expectedFieldViolations := []string{"wallet_address"}
				checkInvalidRequestParams(t, err, expectedFieldViolations)
			},
		},
		{
			name: "unauthorized access",
			req:  refreshAccessTokenReqParams,
			buildStubs: func(store *mockdb.MockStore, cache *mockcache.MockCache) {
			},
			buildContext: func(t *testing.T, tokenMaker token.Maker) context.Context {
				return context.Background()
			},
			checkResponse: func(t *testing.T, res *pb.RefreshAccessTokenResponse, err error) {
				require.Error(t, err)
				require.Empty(t, res)
				require.ErrorContains(t, err, UnauthorizedAccessError)
			},
		},
		{
			name: "no session linked to refresh token",
			req:  refreshAccessTokenReqParams,
			buildStubs: func(store *mockdb.MockStore, cache *mockcache.MockCache) {
				store.EXPECT().
					GetSession(gomock.Any(), gomock.Any()).
					Times(1).
					Return(db.Session{}, db.RecordNotFoundError)
			},
			buildContext: func(t *testing.T, tokenMaker token.Maker) context.Context {
				return newContextWithBearerToken(t, tokenMaker, refreshAccessTokenReqParams.WalletAddress, token.Gamer, token.RefreshToken, 30*time.Second)
			},
			checkResponse: func(t *testing.T, res *pb.RefreshAccessTokenResponse, err error) {
				require.Error(t, err)
				require.Empty(t, res)
				require.ErrorContains(t, err, UnauthorizedAccessError)
			},
		},
		{
			name: "error getting db session",
			req:  refreshAccessTokenReqParams,
			buildStubs: func(store *mockdb.MockStore, cache *mockcache.MockCache) {
				store.EXPECT().
					GetSession(gomock.Any(), gomock.Any()).
					Times(1).
					Return(db.Session{}, errors.New("some db error"))
			},
			buildContext: func(t *testing.T, tokenMaker token.Maker) context.Context {
				return newContextWithBearerToken(t, tokenMaker, refreshAccessTokenReqParams.WalletAddress, token.Gamer, token.RefreshToken, 30*time.Second)
			},
			checkResponse: func(t *testing.T, res *pb.RefreshAccessTokenResponse, err error) {
				require.Error(t, err)
				require.Empty(t, res)
				require.ErrorContains(t, err, InternalServerError)
			},
		},
		{
			name: "db session is revoked",
			req:  refreshAccessTokenReqParams,
			buildStubs: func(store *mockdb.MockStore, cache *mockcache.MockCache) {
				store.EXPECT().
					GetSession(gomock.Any(), gomock.Any()).
					Times(1).
					Return(db.Session{
						ID:           uuid.New(),
						IsRevoked:    true,
						RefreshToken: "refresh_token",
						ExpiresAt:    time.Now().UTC().Add(1 * time.Minute),
					}, nil)
			},
			buildContext: func(t *testing.T, tokenMaker token.Maker) context.Context {
				return newContextWithBearerToken(t, tokenMaker, refreshAccessTokenReqParams.WalletAddress, token.Gamer, token.RefreshToken, 30*time.Second)
			},
			checkResponse: func(t *testing.T, res *pb.RefreshAccessTokenResponse, err error) {
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

			tc.buildStubs(store, cache)

			ctx := tc.buildContext(t, handler.tokenMaker)
			res, err := handler.RefreshAccessToken(ctx, tc.req)
			tc.checkResponse(t, res, err)
		})
	}
}
