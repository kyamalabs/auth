package handler

import (
	"github.com/kyamalabs/auth/api/pb"
	"github.com/kyamalabs/auth/internal/cache"
	db "github.com/kyamalabs/auth/internal/db/sqlc"
	"github.com/kyamalabs/auth/internal/token"
	"github.com/kyamalabs/auth/internal/util"
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
