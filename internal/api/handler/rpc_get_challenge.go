package handler

import (
	"context"

	"github.com/kyamalabs/auth/api/pb"
	"github.com/kyamalabs/auth/internal/challenge"
	"github.com/kyamalabs/auth/internal/validator"
	"github.com/rs/zerolog/log"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (h *Handler) GetChallenge(ctx context.Context, req *pb.GetChallengeRequest) (*pb.GetChallengeResponse, error) {
	logger := log.With().Str("wallet_address", req.GetWalletAddress()).Logger()

	violations := validateGetChallengeRequest(req)
	if violations != nil {
		return nil, invalidArgumentError(violations)
	}

	c, err := challenge.GenerateChallenge(ctx, h.cache, req.GetWalletAddress())
	if err != nil {
		logger.Error().Err(err).Msg("could not create authentication challenge")
		return nil, status.Error(codes.Internal, InternalServerError)
	}

	response := &pb.GetChallengeResponse{
		Challenge: c,
	}

	logger.Info().Str("challenge", c).Msg("auth challenge generated successfully")

	return response, nil
}

func validateGetChallengeRequest(req *pb.GetChallengeRequest) (violations []*errdetails.BadRequest_FieldViolation) {
	if err := validator.ValidateWalletAddress(req.GetWalletAddress()); err != nil {
		violations = append(violations, fieldViolation("wallet_address", err))
	}

	return violations
}
