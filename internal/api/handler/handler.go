package handler

import (
	"github.com/kyamagames/auth/api/pb"
	"github.com/kyamagames/auth/internal/cache"
	db "github.com/kyamagames/auth/internal/db/sqlc"
	"github.com/kyamagames/auth/internal/token"
	"github.com/kyamagames/auth/internal/util"
)

type Handler struct {
	pb.UnimplementedAuthServer
	config     util.Config
	store      db.Store
	tokenMaker token.Maker
	cache      cache.Cache
}

func NewHandler(config util.Config, store db.Store, tokenMaker token.Maker, cache cache.Cache) Handler {
	return Handler{
		config:     config,
		store:      store,
		tokenMaker: tokenMaker,
		cache:      cache,
	}
}
