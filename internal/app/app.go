package app

import (
	grpcapp "authorizationMicroservice/internal/app/grpc"
	"authorizationMicroservice/internal/services/auth"
	"authorizationMicroservice/internal/storage/postgresql"
	"log/slog"
	"time"
)

type App struct {
	GRPCSrv *grpcapp.App
}

func New(
	log *slog.Logger,
	grpcPort int,
	databaseDSN string,
	tokenTTL time.Duration,
) *App {

	storage, err := postgresql.New(databaseDSN)
	if err != nil {
		panic(err)
	}
	authService := auth.New(log, storage, storage, storage, tokenTTL)

	grpcApp := grpcapp.New(log, authService, grpcPort)

	return &App{GRPCSrv: grpcApp}
}
