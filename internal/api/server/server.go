package server

import (
	"fmt"

	"github.com/kyamagames/auth/internal/api/handler"

	db "github.com/kyamagames/auth/internal/db/sqlc"
	"github.com/kyamagames/auth/internal/token"
	"github.com/kyamagames/auth/internal/utils"
)

type Server struct {
	handler.Handler
}

func NewServer(config utils.Config, store db.Store) (*Server, error) {
	tokenMaker, err := token.NewPasetoMaker(config.TokenSymmetricKey)
	if err != nil {
		return nil, fmt.Errorf("cannot create token maker: %w", err)
	}

	server := &Server{
		Handler: handler.NewHandler(config, store, tokenMaker),
	}

	return server, nil
}
