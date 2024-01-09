package server

import (
	"context"
	"fmt"
	"sync"

	"github.com/ulule/limiter/v3"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kyamagames/auth/internal/api/middleware"
	"github.com/kyamagames/auth/internal/cache"

	"github.com/kyamagames/auth/internal/api/handler"

	db "github.com/kyamagames/auth/internal/db/sqlc"
	"github.com/kyamagames/auth/internal/token"
	"github.com/kyamagames/auth/internal/utils"
)

type Server struct {
	handler.Handler
}

var once sync.Once

func NewServer(config utils.Config) (*Server, error) {
	connPool, err := pgxpool.New(context.Background(), config.DBSource)
	if err != nil {
		return nil, fmt.Errorf("cannot connect to db: %w", err)
	}
	store := db.NewStore(connPool)

	tokenMaker, err := token.NewPasetoMaker(config.TokenSymmetricKey)
	if err != nil {
		return nil, fmt.Errorf("cannot create token maker: %w", err)
	}

	redisCache, err := cache.NewRedisCache(config.RedisConnURL)
	if err != nil {
		return nil, fmt.Errorf("cannot create redis cache: %w", err)
	}

	err = setupRateLimiter(config.RedisConnURL)
	if err != nil {
		return nil, err
	}

	server := &Server{
		Handler: handler.NewHandler(config, store, tokenMaker, redisCache),
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
