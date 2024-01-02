package handler

import (
	"github.com/kyamagames/auth/api/pb"
	db "github.com/kyamagames/auth/internal/db/sqlc"
	"github.com/kyamagames/auth/internal/token"
	"github.com/kyamagames/auth/internal/utils"
)

type Handler struct {
	pb.UnimplementedAuthServer
	config     utils.Config
	store      db.Store
	tokenMaker token.Maker
}

func NewHandler(config utils.Config, store db.Store, tokenMaker token.Maker) Handler {
	return Handler{
		config:     config,
		store:      store,
		tokenMaker: tokenMaker,
	}
}
