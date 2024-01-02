package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/rakyll/statik/fs"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kyamagames/auth/api/pb"
	"github.com/kyamagames/auth/api/server"
	db "github.com/kyamagames/auth/internal/db/sqlc"
	"github.com/kyamagames/auth/internal/utils"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	_ "github.com/jackc/pgx/v5"
	_ "github.com/kyamagames/auth/docs/statik"
	"github.com/rs/zerolog/log"
)

func main() {
	config, err := utils.LoadConfig(".")
	if err != nil {
		log.Fatal().Err(err).Msg("cannot load config")
	}

	setupLogger(config)

	connPool, err := pgxpool.New(context.Background(), config.DBSource)
	if err != nil {
		log.Fatal().Err(err).Msg("cannot connect to db")
	}
	store := db.NewStore(connPool)

	runDBMigration(config.DBMigrationURL, config.DBSource)

	go runGatewayServer(config, store)
	runGrpcServer(config, store)
}

func setupLogger(config utils.Config) {
	logger := log.Logger

	if config.Environment == "development" {
		logger = logger.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}

	logger = logger.With().Str("service", "auth").Logger()
	log.Logger = logger
}

func runDBMigration(migrationURL string, dbSource string) {
	migration, err := migrate.New(migrationURL, dbSource)
	if err != nil {
		log.Fatal().Err(err).Msg("cannot create new migration instance")
	}

	err = migration.Up()
	if err != nil && err != migrate.ErrNoChange {
		log.Fatal().Err(err).Msg("failed to run migrate up")
	}

	log.Info().Msg("db migrated successfully")
}

func runGrpcServer(config utils.Config, store db.Store) {
	s, err := server.NewServer(config, store)
	if err != nil {
		log.Fatal().Err(err).Msg("cannot create server")
	}

	grpcServer := grpc.NewServer()
	pb.RegisterAuthServer(grpcServer, s)
	reflection.Register(grpcServer)

	listener, err := net.Listen("tcp", config.GRPCServerAddress)
	if err != nil {
		log.Fatal().Err(err).Msg("cannot create grpc server listener")
	}

	log.Info().Msgf("started gRPC server at %s", listener.Addr().String())
	err = grpcServer.Serve(listener)
	if err != nil {
		log.Fatal().Err(err).Msg("cannot start gRPC server")
	}
}

func runGatewayServer(config utils.Config, store db.Store) {
	s, err := server.NewServer(config, store)
	if err != nil {
		log.Fatal().Err(err).Msg("cannot create server")
	}

	opt := runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.JSONPb{
		MarshalOptions: protojson.MarshalOptions{
			UseProtoNames: true,
		},
		UnmarshalOptions: protojson.UnmarshalOptions{
			DiscardUnknown: true,
		},
	})

	grpcMux := runtime.NewServeMux(opt)

	ctx, cancel := context.WithCancel(context.Background())

	err = pb.RegisterAuthHandlerServer(ctx, grpcMux, s)
	if err != nil {
		log.Fatal().Err(err).Msg("cannot register auth handler server")
	}

	mux := http.NewServeMux()
	mux.Handle("/", grpcMux)

	statikFS, err := fs.New()
	if err != nil {
		log.Fatal().Err(err).Msg("cannot create statik fs")
	}

	swaggerHandler := http.StripPrefix("/swagger/", http.FileServer(statikFS))
	mux.Handle("/swagger/", swaggerHandler)

	srv := &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	listener, err := net.Listen("tcp", config.HTTPServerAddress)
	if err != nil {
		log.Fatal().Err(err).Msg("cannot create http gateway server listener")
	}

	log.Info().Msgf("started HTTP gateway server at %s", listener.Addr().String())

	err = srv.Serve(listener)
	if err != nil {
		log.Fatal().Err(err).Msg("cannot start HTTP gateway server")
	}

	cancel()
}
