package handler

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	mockcache "github.com/kyamagames/auth/internal/cache/mock"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/status"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/kyamagames/auth/api/pb"
	mockdb "github.com/kyamagames/auth/internal/db/mock"
	db "github.com/kyamagames/auth/internal/db/sqlc"
	"github.com/kyamagames/auth/internal/token"
	"github.com/kyamagames/auth/internal/utils"
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
	wallet, err := utils.NewEthereumWallet()
	require.NoError(t, err)
	require.NotEmpty(t, wallet)

	authChallenge := gofakeit.Phrase()

	signature, err := utils.SignMessageEthereum(wallet.PrivateKey, authChallenge)
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
		buildStubs    func(store *mockdb.MockStore)
		checkResponse func(t *testing.T, res *pb.AuthenticateAccountResponse, err error)
	}{
		{
			name: "Success",
			req:  authenticateAccountReqParams,
			buildStubs: func(store *mockdb.MockStore) {
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
				Challenge:     authenticateAccountReqParams.GetChallenge(),
				Signature:     "invalid_signature",
			},
			buildStubs: func(store *mockdb.MockStore) {
			},
			checkResponse: func(t *testing.T, res *pb.AuthenticateAccountResponse, err error) {
				require.Error(t, err)
				require.Empty(t, res)

				var violations []string
				expectedFieldViolations := []string{"wallet_address", "signature"}

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
			name: "Failure - invalid signature",
			req: &pb.AuthenticateAccountRequest{
				WalletAddress: authenticateAccountReqParams.GetWalletAddress(),
				Challenge:     authenticateAccountReqParams.GetChallenge(),
				Signature:     fmt.Sprintf("%sz", authenticateAccountReqParams.GetSignature()[:len(authenticateAccountReqParams.GetSignature())-1]),
			},
			buildStubs: func(store *mockdb.MockStore) {
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
			buildStubs: func(store *mockdb.MockStore) {
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
			buildStubs: func(store *mockdb.MockStore) {
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
			buildStubs: func(store *mockdb.MockStore) {
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

			tc.buildStubs(store)

			handler := newTestHandler(t, store, cache)

			res, err := handler.AuthenticateAccount(context.Background(), tc.req)
			tc.checkResponse(t, res, err)
		})
	}
}
