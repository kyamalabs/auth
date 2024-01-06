package handler

import (
	"context"
	"testing"

	"github.com/kyamagames/auth/api/pb"
	mockcache "github.com/kyamagames/auth/internal/cache/mock"
	mockdb "github.com/kyamagames/auth/internal/db/mock"
	"github.com/kyamagames/auth/internal/utils"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestGetChallengeAPI(t *testing.T) {
	wallet, err := utils.NewEthereumWallet()
	require.NoError(t, err)
	require.NotEmpty(t, wallet)

	testCases := []struct {
		name          string
		req           *pb.GetChallengeRequest
		buildStubs    func(cache *mockcache.MockCache)
		checkResponse func(t *testing.T, res *pb.GetChallengeResponse, err error)
	}{
		{
			name: "Success",
			req: &pb.GetChallengeRequest{
				WalletAddress: wallet.Address,
			},
			buildStubs: func(cache *mockcache.MockCache) {
				cache.EXPECT().
					Set(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Times(1).
					Return(nil)
			},
			checkResponse: func(t *testing.T, res *pb.GetChallengeResponse, err error) {
				require.NoError(t, err)
				require.NotEmpty(t, res)
			},
		},
		{
			name: "Failure - invalid request arguments",
			req: &pb.GetChallengeRequest{
				WalletAddress: "99357D102b4B0714FD26A221a18F354d650bD1762b",
			},
			buildStubs: func(cache *mockcache.MockCache) {
			},
			checkResponse: func(t *testing.T, res *pb.GetChallengeResponse, err error) {
				require.Error(t, err)
				require.Empty(t, res)

				expectedFieldViolations := []string{"wallet_address"}
				checkInvalidRequestParams(t, err, expectedFieldViolations)
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

			tc.buildStubs(cache)

			handler := newTestHandler(t, store, cache)

			res, err := handler.GetChallenge(context.Background(), tc.req)
			tc.checkResponse(t, res, err)
		})
	}
}
