package auth

import (
	"authorizationMicroservice/internal/domain/models"
	"authorizationMicroservice/internal/lib/jwt"
	"authorizationMicroservice/internal/storage"
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"time"
)

type Auth struct {
	log         *slog.Logger
	usrProvider UserProvider
	usrSaver    UserSaver
	appProvider AppProvider
	tokenTTL    time.Duration
}

type UserSaver interface {
	SaveUser(
		ctx context.Context,
		email string,
		passHash []byte,
	) (uid int64, err error)
}

type UserProvider interface {
	User(ctx context.Context, email string) (*models.User, error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
}

type AppProvider interface {
	App(ctx context.Context, appID int) (*models.App, error)
}

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserExists         = errors.New("user already exists")
	ErrInvalidAppID       = errors.New("invalid app id")
)

// New returns a new instance of the Auth service.
func New(
	log *slog.Logger,
	usrProvider UserProvider,
	usrSaver UserSaver,
	appProvider AppProvider,
	tokenTTL time.Duration,
) *Auth {
	return &Auth{
		log:         log,
		usrProvider: usrProvider,
		usrSaver:    usrSaver,
		appProvider: appProvider,
		tokenTTL:    tokenTTL,
	}
}

func (a *Auth) Login(
	ctx context.Context,
	email string,
	password string,
	appID int,
) (string, error) {
	const op = "auth.Login"

	log := a.log.With(slog.String("op", op))

	log.Info("attempting to login user")

	user, err := a.usrProvider.User(ctx, email)
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrUserNotFound):
			log.Error(storage.ErrUserNotFound.Error(), slog.Attr{
				Key:   "error",
				Value: slog.StringValue(err.Error()),
			})

			return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		default:
			log.Error("failed to get user", slog.Attr{
				Key:   "error",
				Value: slog.StringValue(err.Error()),
			})
			return "", fmt.Errorf("%s: %w", op, err)
		}
	}

	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		log.Info("invalid credentials", slog.Attr{
			Key:   "error",
			Value: slog.StringValue(err.Error()),
		})
		return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	token, err := jwt.NewToken(user, app, a.tokenTTL)
	if err != nil {
		log.Error("failed to generate token", slog.Attr{
			Key:   "error",
			Value: slog.StringValue(err.Error()),
		})

		return "", fmt.Errorf("%s: %w", op, err)
	}

	return token, nil
}

func (a *Auth) Register(
	ctx context.Context,
	email string,
	password string,
) (userID int64, err error) {
	const op = "auth.Register"

	log := a.log.With(slog.String("op", op))

	log.Info("registering user")

	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to generate password hash", slog.Attr{
			Key:   "error",
			Value: slog.StringValue(err.Error()),
		})

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	userID, err = a.usrSaver.SaveUser(ctx, email, passHash)
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrUserExists):
			log.Error("user already exists", slog.Attr{
				Key:   "error",
				Value: slog.StringValue(err.Error()),
			})
			return 0, fmt.Errorf("%s: %w", op, ErrUserExists)

		default:
			log.Error("failed to save user", slog.Attr{
				Key:   "error",
				Value: slog.StringValue(err.Error()),
			})
			return 0, fmt.Errorf("%s: %w", op, err)
		}

	}

	log.Info("user registered")

	return userID, nil
}

func (a *Auth) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	const op = "auth.IsAdmin"

	log := a.log.With(slog.String("op", op))

	log.Info("checking if the user is admin")

	isAdmin, err := a.usrProvider.IsAdmin(ctx, userID)
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrAppNotFound):
			log.Warn("app not found", slog.Attr{
				Key:   "error",
				Value: slog.StringValue(err.Error()),
			})
			return false, fmt.Errorf("%s: %w", op, ErrInvalidAppID)
		default:
			return false, fmt.Errorf("%s: %w", op, err)
		}

	}

	return isAdmin, nil
}
