package server

import (
	"fmt"
	"sync"

	"github.com/ulule/limiter/v3"

	"github.com/kyamalabs/auth/internal/api/middleware"
	"github.com/kyamalabs/auth/internal/cache"

	"github.com/kyamalabs/auth/internal/api/handler"

	db "github.com/kyamalabs/auth/internal/db/sqlc"
	"github.com/kyamalabs/auth/internal/token"
	"github.com/kyamalabs/auth/internal/util"
)

type Server struct {
	handler.Handler
}

var once sync.Once

func NewServer(config util.Config, store db.Store, cache cache.Cache) (*Server, error) {
	tokenMaker, err := token.NewPasetoMaker(config.TokenSymmetricKey)
	if err != nil {
		return nil, fmt.Errorf("cannot create token maker: %w", err)
	}

	err = setupRateLimiter(config.RedisConnURL)
	if err != nil {
		return nil, err
	}

	server := &Server{
		Handler: handler.NewHandler(config, store, tokenMaker, cache),
	}

	return server, nil
}

func setupRateLimiter(redisConnURL string) error {
	var store limiter.Store
	var createLimiterRedisStoreErr, initializeLimitersErr error

	once.Do(func() {
		store, createLimiterRedisStoreErr = middleware.CreateLimiterRedisStore(redisConnURL)
		if createLimiterRedisStoreErr == nil {
			initializeLimitersErr = middleware.InitializeLimiters(store)
		}
	})

	if createLimiterRedisStoreErr != nil {
		return fmt.Errorf("could not create limiter redis client: %w", createLimiterRedisStoreErr)
	}
	if initializeLimitersErr != nil {
		return fmt.Errorf("could not initialize rate limiters: %w", initializeLimitersErr)
	}

	return nil
}
