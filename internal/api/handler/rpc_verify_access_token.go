package handler

import (
	"context"
	"strings"

	"github.com/kyamagames/auth/api/pb"
	"github.com/kyamagames/auth/internal/api/middleware"
	"github.com/kyamagames/auth/internal/token"
	"github.com/kyamagames/auth/internal/validator"
	"github.com/rs/zerolog/log"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (h *Handler) VerifyAccessToken(ctx context.Context, req *pb.VerifyAccessTokenRequest) (*pb.VerifyAccessTokenResponse, error) {
	logger := log.With().Str("wallet_address", req.GetWalletAddress()).Logger()

	violations := validateVerifyAccessTokenRequest(req)
	if violations != nil {
		return nil, invalidArgumentError(violations)
	}

	authPayload, err := middleware.AuthorizeAccount(ctx, req.GetWalletAddress(), h.tokenMaker, token.AccessToken, []token.Role{token.Gamer})
	if err != nil {
		logger.Error().Err(err).Msg("could not authorize account")
		return nil, status.Error(codes.Unauthenticated, UnauthorizedAccessError)
	}

	payloadRoleIdx, ok := pb.AccessTokenPayload_Role_value[strings.ToUpper(string(authPayload.Role))]
	if !ok {
		logger.Error().Str("account_role", string(authPayload.Role)).Msg("could not map account's role to access token payload role")
		return nil, status.Error(codes.Unauthenticated, InternalServerError)
	}
	payloadRole := pb.AccessTokenPayload_Role(payloadRoleIdx)

	response := &pb.VerifyAccessTokenResponse{
		Payload: &pb.AccessTokenPayload{
			Id:            authPayload.ID.String(),
			WalletAddress: authPayload.WalletAddress,
			Role:          payloadRole,
			IssuedAt:      timestamppb.New(authPayload.IssuedAt),
			ExpiresAt:     timestamppb.New(authPayload.ExpiresAt),
		},
	}

	return response, nil
}

func validateVerifyAccessTokenRequest(req *pb.VerifyAccessTokenRequest) (violations []*errdetails.BadRequest_FieldViolation) {
	if err := validator.ValidateWalletAddress(req.GetWalletAddress()); err != nil {
		violations = append(violations, fieldViolation("wallet_address", err))
	}

	return violations
}
