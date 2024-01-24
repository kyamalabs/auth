package handler

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kyamalabs/auth/pkg/util"

	"github.com/brianvoe/gofakeit/v6"
	mockcache "github.com/kyamalabs/auth/internal/cache/mock"
	"github.com/kyamalabs/auth/internal/challenge"

	"github.com/google/uuid"
	"github.com/kyamalabs/auth/api/pb"
	mockdb "github.com/kyamalabs/auth/internal/db/mock"
	db "github.com/kyamalabs/auth/internal/db/sqlc"
	"github.com/kyamalabs/auth/internal/token"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type eqCreateSessionParamsMatcher struct {
	arg db.CreateSessionParams
}

func (expected eqCreateSessionParamsMatcher) Matches(x interface{}) bool {
	actualArg, ok := x.(db.CreateSessionParams)
	if !ok {
		return false
	}

	if actualArg.WalletAddress != expected.arg.WalletAddress {
		return false
	}

	return true
}

func (expected eqCreateSessionParamsMatcher) String() string {
	return fmt.Sprintf("matches arg %v", expected.arg)
}

func EqCreateSessionParams(arg db.CreateSessionParams) gomock.Matcher {
	return eqCreateSessionParamsMatcher{arg: arg}
}

func generateTestAuthenticateAccountReqParams(t *testing.T) *pb.AuthenticateAccountRequest {
	wallet, err := util.NewEthereumWallet()
	require.NoError(t, err)
	require.NotEmpty(t, wallet)

	crtl := gomock.NewController(t)
	defer crtl.Finish()

	cache := mockcache.NewMockCache(crtl)

	cache.EXPECT().
		Set(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Times(1).
		Return(nil)

	authChallenge, err := challenge.GenerateChallenge(context.Background(), cache, wallet.Address)
	require.NoError(t, err)

	signature, err := util.SignMessageEthereum(wallet.PrivateKey, authChallenge)
	require.NoError(t, err)
	require.NotEmpty(t, signature)

	return &pb.AuthenticateAccountRequest{
		WalletAddress: wallet.Address,
		Challenge:     authChallenge,
		Signature:     signature,
	}
}

func TestAuthenticateAccountAPI(t *testing.T) {
	authenticateAccountReqParams := generateTestAuthenticateAccountReqParams(t)
	require.NotEmpty(t, authenticateAccountReqParams)

	testCases := []struct {
		name          string
		req           *pb.AuthenticateAccountRequest
		buildStubs    func(store *mockdb.MockStore, cache *mockcache.MockCache)
		checkResponse func(t *testing.T, res *pb.AuthenticateAccountResponse, err error)
	}{
		{
			name: "Success",
			req:  authenticateAccountReqParams,
			buildStubs: func(store *mockdb.MockStore, cache *mockcache.MockCache) {
				cache.EXPECT().
					Get(gomock.Any(), gomock.Any()).
					Times(1).
					Return(authenticateAccountReqParams.GetChallenge(), nil)

				cache.EXPECT().
					Del(gomock.Any(), gomock.Any()).
					Times(1).
					Return(nil)

				store.EXPECT().
					GetAccountByOwner(gomock.Any(), authenticateAccountReqParams.WalletAddress).
					Times(1).
					Return(db.Account{}, db.RecordNotFoundError)

				store.EXPECT().
					CreateAccount(gomock.Any(), authenticateAccountReqParams.WalletAddress).
					Times(1).
					Return(db.Account{
						ID:        uuid.New(),
						Owner:     authenticateAccountReqParams.WalletAddress,
						Role:      db.Role(token.Gamer),
						CreatedAt: time.Now().UTC(),
					}, nil)

				store.EXPECT().
					CreateSession(gomock.Any(), EqCreateSessionParams(db.CreateSessionParams{
						WalletAddress: authenticateAccountReqParams.WalletAddress,
					})).
					Times(1).
					Return(db.Session{
						ID: uuid.New(),
					}, nil)
			},
			checkResponse: func(t *testing.T, res *pb.AuthenticateAccountResponse, err error) {
				require.NoError(t, err)
				require.NotEmpty(t, res)

				require.Equal(t, authenticateAccountReqParams.GetWalletAddress(), res.GetAccount().GetOwner())
				require.Equal(t, "bearer", strings.ToLower(res.GetSession().GetTokenType()))
			},
		},
		{
			name: "Failure - invalid request arguments",
			req: &pb.AuthenticateAccountRequest{
				WalletAddress: "0x0000000000000000000000000000000000000000",
				Challenge:     gofakeit.Phrase(),
				Signature:     "invalid_signature",
			},
			buildStubs: func(store *mockdb.MockStore, _ *mockcache.MockCache) {
			},
			checkResponse: func(t *testing.T, res *pb.AuthenticateAccountResponse, err error) {
				require.Error(t, err)
				require.Empty(t, res)

				expectedFieldViolations := []string{"wallet_address", "challenge", "signature"}
				checkInvalidRequestParams(t, err, expectedFieldViolations)
			},
		},
		{
			name: "Failure - could not get cached challenge",
			req:  authenticateAccountReqParams,
			buildStubs: func(_ *mockdb.MockStore, cache *mockcache.MockCache) {
				cache.EXPECT().
					Get(gomock.Any(), gomock.Any()).
					Times(1).
					Return("", errors.New("some cache error"))
			},
			checkResponse: func(t *testing.T, res *pb.AuthenticateAccountResponse, err error) {
				require.Empty(t, res)
				require.Error(t, err)
				require.ErrorContains(t, err, InvalidChallengeError)
			},
		},
		{
			name: "Failure - cached challenge is empty",
			req:  authenticateAccountReqParams,
			buildStubs: func(_ *mockdb.MockStore, cache *mockcache.MockCache) {
				cache.EXPECT().
					Get(gomock.Any(), gomock.Any()).
					Times(1).
					Return("", nil)

				cache.EXPECT().
					Del(gomock.Any(), gomock.Any()).
					Times(1).
					Return(nil)
			},
			checkResponse: func(t *testing.T, res *pb.AuthenticateAccountResponse, err error) {
				require.Empty(t, res)
				require.Error(t, err)
				require.ErrorContains(t, err, InvalidChallengeError)
			},
		},
		{
			name: "Failure - cached challenge does not match request challenge",
			req:  authenticateAccountReqParams,
			buildStubs: func(_ *mockdb.MockStore, cache *mockcache.MockCache) {
				cache.EXPECT().
					Get(gomock.Any(), gomock.Any()).
					Times(1).
					Return("Kyama Games: Pixie-bob: 6859", nil)

				cache.EXPECT().
					Del(gomock.Any(), gomock.Any()).
					Times(1).
					Return(nil)
			},
			checkResponse: func(t *testing.T, res *pb.AuthenticateAccountResponse, err error) {
				require.Empty(t, res)
				require.Error(t, err)
				require.ErrorContains(t, err, InvalidChallengeError)
			},
		},
		{
			name: "Failure - invalid signature",
			req: &pb.AuthenticateAccountRequest{
				WalletAddress: authenticateAccountReqParams.GetWalletAddress(),
				Challenge:     authenticateAccountReqParams.GetChallenge(),
				Signature:     fmt.Sprintf("%sz", authenticateAccountReqParams.GetSignature()[:len(authenticateAccountReqParams.GetSignature())-1]),
			},
			buildStubs: func(store *mockdb.MockStore, cache *mockcache.MockCache) {
				cache.EXPECT().
					Get(gomock.Any(), gomock.Any()).
					Times(1).
					Return(authenticateAccountReqParams.GetChallenge(), nil)

				cache.EXPECT().
					Del(gomock.Any(), gomock.Any()).
					Times(1).
					Return(nil)
			},
			checkResponse: func(t *testing.T, res *pb.AuthenticateAccountResponse, err error) {
				require.Empty(t, res)
				require.Error(t, err)
				require.ErrorContains(t, err, SignatureVerificationError)
			},
		},
		{
			name: "Failure - could not get account by owner",
			req:  authenticateAccountReqParams,
			buildStubs: func(store *mockdb.MockStore, cache *mockcache.MockCache) {
				cache.EXPECT().
					Get(gomock.Any(), gomock.Any()).
					Times(1).
					Return(authenticateAccountReqParams.GetChallenge(), nil)

				cache.EXPECT().
					Del(gomock.Any(), gomock.Any()).
					Times(1).
					Return(nil)

				store.EXPECT().
					GetAccountByOwner(gomock.Any(), authenticateAccountReqParams.WalletAddress).
					Times(1).
					Return(db.Account{}, errors.New("some db error"))
			},
			checkResponse: func(t *testing.T, res *pb.AuthenticateAccountResponse, err error) {
				require.Empty(t, res)
				require.Error(t, err)
				require.ErrorContains(t, err, InternalServerError)
			},
		},
		{
			name: "Failure - could not create new account",
			req:  authenticateAccountReqParams,
			buildStubs: func(store *mockdb.MockStore, cache *mockcache.MockCache) {
				cache.EXPECT().
					Get(gomock.Any(), gomock.Any()).
					Times(1).
					Return(authenticateAccountReqParams.GetChallenge(), nil)

				cache.EXPECT().
					Del(gomock.Any(), gomock.Any()).
					Times(1).
					Return(nil)

				store.EXPECT().
					GetAccountByOwner(gomock.Any(), authenticateAccountReqParams.WalletAddress).
					Times(1).
					Return(db.Account{}, db.RecordNotFoundError)

				store.EXPECT().
					CreateAccount(gomock.Any(), authenticateAccountReqParams.WalletAddress).
					Times(1).
					Return(db.Account{}, errors.New("some db error"))
			},
			checkResponse: func(t *testing.T, res *pb.AuthenticateAccountResponse, err error) {
				require.Empty(t, res)
				require.Error(t, err)
				require.ErrorContains(t, err, InternalServerError)
			},
		},
		{
			name: "Failure - could not create new db session",
			req:  authenticateAccountReqParams,
			buildStubs: func(store *mockdb.MockStore, cache *mockcache.MockCache) {
				cache.EXPECT().
					Get(gomock.Any(), gomock.Any()).
					Times(1).
					Return(authenticateAccountReqParams.GetChallenge(), nil)

				cache.EXPECT().
					Del(gomock.Any(), gomock.Any()).
					Times(1).
					Return(nil)

				store.EXPECT().
					GetAccountByOwner(gomock.Any(), authenticateAccountReqParams.WalletAddress).
					Times(1).
					Return(db.Account{}, db.RecordNotFoundError)

				store.EXPECT().
					CreateAccount(gomock.Any(), authenticateAccountReqParams.WalletAddress).
					Times(1).
					Return(db.Account{
						ID:        uuid.New(),
						Owner:     authenticateAccountReqParams.WalletAddress,
						Role:      db.Role(token.Gamer),
						CreatedAt: time.Now().UTC(),
					}, nil)

				store.EXPECT().
					CreateSession(gomock.Any(), EqCreateSessionParams(db.CreateSessionParams{
						WalletAddress: authenticateAccountReqParams.WalletAddress,
					})).
					Return(db.Session{}, errors.New("some db error"))
			},
			checkResponse: func(t *testing.T, res *pb.AuthenticateAccountResponse, err error) {
				require.Empty(t, res)
				require.Error(t, err)
				require.ErrorContains(t, err, InternalServerError)
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

			tc.buildStubs(store, cache)

			handler := newTestHandler(t, store, cache)

			res, err := handler.AuthenticateAccount(context.Background(), tc.req)
			tc.checkResponse(t, res, err)
		})
	}
}
