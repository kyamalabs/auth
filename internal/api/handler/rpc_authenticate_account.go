package handler

import (
	"context"

	"github.com/kyamagames/auth/internal/token"

	"github.com/kyamagames/auth/internal/challenge"
	"github.com/kyamagames/auth/internal/validator"
	"google.golang.org/genproto/googleapis/rpc/errdetails"

	"github.com/kyamagames/auth/api/pb"
	db "github.com/kyamagames/auth/internal/db/sqlc"
	"github.com/kyamagames/auth/internal/util"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (h *Handler) AuthenticateAccount(ctx context.Context, req *pb.AuthenticateAccountRequest) (*pb.AuthenticateAccountResponse, error) {
	logger := log.With().Str("wallet_address", req.GetWalletAddress()).Logger()

	violations := validateAuthenticateAccountRequest(req)
	if violations != nil {
		return nil, invalidArgumentError(violations)
	}

	cachedChallenge, err := challenge.FetchChallenge(ctx, h.cache, req.GetWalletAddress())
	if err != nil || cachedChallenge == "" {
		logger.Error().Err(err).Msg("could not fetch cached challenge")
		return nil, status.Error(codes.InvalidArgument, InvalidChallengeError)
	}

	if req.GetChallenge() != cachedChallenge {
		logger.Error().
			Str("request_challenge", req.GetChallenge()).
			Str("cached_challenge", cachedChallenge).
			Msg("request challenge did not match cached challenge")
		return nil, status.Error(codes.InvalidArgument, InvalidChallengeError)
	}

	isSignatureValid, err := util.IsEthereumSignatureValid(req.GetWalletAddress(), req.GetChallenge(), req.GetSignature())
	if err != nil || !isSignatureValid {
		logger.Error().Err(err).Msg("authentication challenge signature not valid")
		return nil, status.Error(codes.InvalidArgument, SignatureVerificationError)
	}

	account, err := h.store.GetAccountByOwner(ctx, req.GetWalletAddress())
	if err != nil && err != db.RecordNotFoundError {
		logger.Error().Err(err).Msg("could not fetch account by owner")
		return nil, status.Error(codes.Internal, InternalServerError)
	}

	if account == (db.Account{}) {
		account, err = h.store.CreateAccount(ctx, req.GetWalletAddress())
		if err != nil {
			logger.Error().Err(err).Msg("could not create account in db")
			return nil, status.Error(codes.Internal, InternalServerError)
		}
	}

	session, err := NewSession(ctx, account.Owner, token.Role(account.Role), h.config, h.tokenMaker, h.store)
	if err != nil {
		logger.Error().Err(err).Msg("could not create account session")
		return nil, status.Error(codes.Internal, InternalServerError)
	}

	response := &pb.AuthenticateAccountResponse{
		Account: &pb.Account{
			Id:        account.ID.String(),
			Owner:     account.Owner,
			CreatedAt: timestamppb.New(account.CreatedAt),
		},
		Session: &pb.Session{
			SessionId:             session.ID,
			AccessToken:           session.AccessToken,
			RefreshToken:          session.RefreshToken,
			AccessTokenExpiresAt:  timestamppb.New(session.AccessTokenPayload.ExpiresAt),
			RefreshTokenExpiresAt: timestamppb.New(session.RefreshTokenPayload.ExpiresAt),
			TokenType:             "bearer",
		},
	}

	logger.Info().Str("account_id", account.ID.String()).Msg("account authenticated successfully")

	return response, nil
}

func validateAuthenticateAccountRequest(req *pb.AuthenticateAccountRequest) (violations []*errdetails.BadRequest_FieldViolation) {
	if err := validator.ValidateWalletAddress(req.GetWalletAddress()); err != nil {
		violations = append(violations, fieldViolation("wallet_address", err))
	}

	if err := challenge.ValidateChallenge(req.GetChallenge()); err != nil {
		violations = append(violations, fieldViolation("challenge", err))
	}

	if err := validator.ValidateEthereumSignature(req.GetSignature()); err != nil {
		violations = append(violations, fieldViolation("signature", err))
	}

	return violations
}
