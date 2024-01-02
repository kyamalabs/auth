package server

import (
	"context"

	"github.com/kyamagames/auth/internal/validator"
	"google.golang.org/genproto/googleapis/rpc/errdetails"

	"github.com/kyamagames/auth/api/pb"
	db "github.com/kyamagames/auth/internal/db/sqlc"
	"github.com/kyamagames/auth/internal/token"
	"github.com/kyamagames/auth/internal/utils"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (server *Server) AuthenticateAccount(ctx context.Context, req *pb.AuthenticateAccountRequest) (*pb.AuthenticateAccountResponse, error) {
	logger := log.With().Str("wallet_address", req.GetWalletAddress()).Logger()

	violations := validateAuthenticateAccountRequest(req)
	if violations != nil {
		return nil, invalidArgumentError(violations)
	}

	isSignatureValid, err := utils.IsEthereumSignatureValid(req.GetWalletAddress(), req.GetChallenge(), req.GetSignature())
	if err != nil || !isSignatureValid {
		logger.Error().Err(err).Msg("authentication challenge signature not valid")
		return nil, status.Error(codes.InvalidArgument, SignatureVerificationError)
	}

	account, err := server.store.GetAccountByOwner(ctx, req.GetWalletAddress())
	if err != nil && err != db.RecordNotFoundError {
		logger.Error().Err(err).Msg("could not fetch account by owner")
		return nil, status.Error(codes.Internal, InternalServerError)
	}

	if account == (db.Account{}) {
		account, err = server.store.CreateAccount(ctx, req.GetWalletAddress())
		if err != nil {
			logger.Error().Err(err).Msg("could not create account in db")
			return nil, status.Error(codes.Internal, InternalServerError)
		}
	}

	accessToken, accessTokenPayload, err := server.tokenMaker.CreateToken(req.GetWalletAddress(), token.Gamer, server.config.AccessTokenDuration)
	if err != nil {
		logger.Error().Err(err).Msg("could not create access token")
		return nil, status.Error(codes.Internal, InternalServerError)
	}

	refreshToken, refreshTokenPayload, err := server.tokenMaker.CreateToken(req.GetWalletAddress(), token.Gamer, server.config.RefreshTokenDuration)
	if err != nil {
		logger.Error().Err(err).Msg("could not create refresh token token")
		return nil, status.Error(codes.Internal, InternalServerError)
	}

	metadata := server.extractMetadata(ctx)

	session, err := server.store.CreateSession(ctx, db.CreateSessionParams{
		ID:            refreshTokenPayload.ID,
		WalletAddress: req.GetWalletAddress(),
		RefreshToken:  refreshToken,
		UserAgent:     metadata.UserAgent,
		ClientIp:      metadata.ClientIP,
		ExpiresAt:     refreshTokenPayload.ExpiresAt,
	})
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
			SessionId:             session.ID.String(),
			AccessToken:           accessToken,
			RefreshToken:          refreshToken,
			AccessTokenExpiresAt:  timestamppb.New(accessTokenPayload.ExpiresAt),
			RefreshTokenExpiresAt: timestamppb.New(refreshTokenPayload.ExpiresAt),
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

	if err := validator.ValidateChallenge(req.GetChallenge(), ""); err != nil {
		violations = append(violations, fieldViolation("challenge", err))
	}

	if err := validator.ValidateEthereumSignature(req.GetSignature()); err != nil {
		violations = append(violations, fieldViolation("signature", err))
	}

	return violations
}
