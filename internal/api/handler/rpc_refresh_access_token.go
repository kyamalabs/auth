package handler

import (
	"context"

	"github.com/kyamagames/auth/api/pb"
	"github.com/kyamagames/auth/internal/api/middleware"
	db "github.com/kyamagames/auth/internal/db/sqlc"
	"github.com/kyamagames/auth/internal/token"
	"github.com/kyamagames/auth/internal/validator"
	"github.com/rs/zerolog/log"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (h *Handler) RefreshAccessToken(ctx context.Context, req *pb.RefreshAccessTokenRequest) (*pb.RefreshAccessTokenResponse, error) {
	logger := log.With().Str("wallet_address", req.GetWalletAddress()).Logger()

	violations := validateRefreshAccessTokenRequest(req)
	if violations != nil {
		return nil, invalidArgumentError(violations)
	}

	authPayload, err := middleware.AuthorizeAccount(ctx, req.GetWalletAddress(), h.tokenMaker, []token.Role{token.Gamer})
	if err != nil {
		logger.Error().Err(err).Msg("could not authorize account")
		return nil, status.Error(codes.Unauthenticated, UnauthorizedAccessError)
	}

	session, err := h.store.GetSession(ctx, authPayload.ID)
	if err == db.RecordNotFoundError {
		logger.Error().Err(err).Msg("could not get account session")
		return nil, status.Error(codes.Unauthenticated, UnauthorizedAccessError)
	} else if err != nil {
		logger.Error().Err(err).Msg("could not get account session")
		return nil, status.Error(codes.Unauthenticated, InternalServerError)
	}

	if session.IsRevoked {
		logger.Error().Str("session_id", session.ID.String()).Msg("session is revoked")
		return nil, status.Error(codes.Unauthenticated, UnauthorizedAccessError)
	}

	accessToken, accessTokenPayload, err := h.tokenMaker.CreateToken(req.GetWalletAddress(), authPayload.Role, h.config.AccessTokenDuration)
	if err != nil {
		logger.Error().Err(err).Msg("could not create access token")
		return nil, status.Error(codes.Unauthenticated, InternalServerError)
	}

	response := &pb.RefreshAccessTokenResponse{
		Session: &pb.Session{
			SessionId:             session.ID.String(),
			AccessToken:           accessToken,
			RefreshToken:          session.RefreshToken,
			AccessTokenExpiresAt:  timestamppb.New(accessTokenPayload.ExpiresAt),
			RefreshTokenExpiresAt: timestamppb.New(session.ExpiresAt),
			TokenType:             "bearer",
		},
	}

	logger.Info().Msg("refreshed access token successfully")

	return response, nil
}

func validateRefreshAccessTokenRequest(req *pb.RefreshAccessTokenRequest) (violations []*errdetails.BadRequest_FieldViolation) {
	if err := validator.ValidateWalletAddress(req.GetWalletAddress()); err != nil {
		violations = append(violations, fieldViolation("wallet_address", err))
	}

	return violations
}
