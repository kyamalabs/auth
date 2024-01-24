package handler

import (
	"context"

	"github.com/kyamalabs/auth/api/pb"
	"github.com/kyamalabs/auth/internal/api/middleware"
	"github.com/kyamalabs/auth/internal/token"
	"github.com/kyamalabs/auth/internal/validator"
	"github.com/rs/zerolog/log"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (h *Handler) RevokeRefreshTokens(ctx context.Context, req *pb.RevokeRefreshTokensRequest) (*pb.RevokeRefreshTokensResponse, error) {
	logger := log.With().Str("wallet_address", req.GetWalletAddress()).Logger()

	violations := validateRevokeRefreshTokensRequest(req)
	if violations != nil {
		return nil, invalidArgumentError(violations)
	}

	_, err := middleware.AuthorizeAccount(ctx, req.GetWalletAddress(), h.tokenMaker, token.AccessToken, []token.Role{token.Gamer, token.Admin})
	if err != nil {
		logger.Error().Err(err).Msg("could not authorize account")
		return nil, status.Error(codes.Unauthenticated, UnauthorizedAccessError)
	}

	ct, err := h.store.RevokeAccountSessions(ctx, req.GetWalletAddress())
	if err != nil {
		logger.Error().Err(err).Msg("could not revoke account sessions")
		return nil, status.Error(codes.Unauthenticated, InternalServerError)
	}

	response := &pb.RevokeRefreshTokensResponse{
		NumSessionsRevoked: ct.RowsAffected(),
	}

	logger.Info().Int64("num_sessions_revoked", ct.RowsAffected()).Msg("successfully revoked account refresh tokens")

	return response, nil
}

func validateRevokeRefreshTokensRequest(req *pb.RevokeRefreshTokensRequest) (violations []*errdetails.BadRequest_FieldViolation) {
	if err := validator.ValidateWalletAddress(req.GetWalletAddress()); err != nil {
		violations = append(violations, fieldViolation("wallet_address", err))
	}

	return violations
}
