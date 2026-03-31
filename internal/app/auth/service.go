package auth

import (
	"context"
	"errors"
	"prohojemba-go/internal/domain"
	"time"
)

var ErrUserNotFound = errors.New("user not found")
var ErrInvalidCredentials = errors.New("invalid credentials")

type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(password string, hash string) bool
}

type TokensPair struct {
	AccessToken           string
	RefreshToken          string
	AccessTokenExpiresAt  time.Time
	RefreshTokenExpiresAt time.Time
	TokenType             string
}

type TokensIssuer interface {
	Issue(ctx context.Context, userId uint, accessTTL time.Duration, refreshTTL time.Duration) (TokensPair, error)
}

type UsersRepo interface {
	GetByUsername(ctx context.Context, username string) (domain.User, error)
}

type RefreshTokensRepo interface {
	Store(ctx context.Context, userId uint, token string, expiresAt time.Time) error
	Rotate(ctx context.Context, oldToken string, newToken string, newExpiresAt time.Time) error
	GetByToken(ctx context.Context, token string) (struct {
		UserId    uint
		ExpiresAt time.Time
	}, error)
}

type Service struct {
	users      UsersRepo
	tokens     RefreshTokensRepo
	hasher     PasswordHasher
	issuer     TokensIssuer
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func NewService(users UsersRepo, tokens RefreshTokensRepo, hasher PasswordHasher, tokensIssuer TokensIssuer, accessTTL time.Duration, refreshTTL time.Duration) *Service {
	return &Service{users: users, tokens: tokens, hasher: hasher, issuer: tokensIssuer, accessTTL: accessTTL, refreshTTL: refreshTTL}
}

func (s *Service) Login(ctx context.Context, username string, password string) (domain.User, TokensPair, error) {
	user, err := s.users.GetByUsername(ctx, username)
	if err != nil {
		return domain.User{}, TokensPair{}, err
	}
	if !s.hasher.Verify(password, user.HashedPassword) {
		return domain.User{}, TokensPair{}, ErrInvalidCredentials
	}
	tp, err := s.issuer.Issue(ctx, user.Id, s.accessTTL, s.refreshTTL)
	if err != nil {
		return domain.User{}, TokensPair{}, err
	}
	if err := s.tokens.Store(ctx, user.Id, tp.RefreshToken, tp.RefreshTokenExpiresAt); err != nil {
		return domain.User{}, TokensPair{}, err
	}
	return user, tp, nil
}

func (s *Service) Refresh(ctx context.Context, refreshToken string) (TokensPair, error) {
	row, err := s.tokens.GetByToken(ctx, refreshToken)
	if err != nil {
		return TokensPair{}, err
	}
	if time.Now().After(row.ExpiresAt) {
		return TokensPair{}, ErrInvalidCredentials
	}
	tp, err := s.issuer.Issue(ctx, row.UserId, s.accessTTL, s.refreshTTL)
	if err != nil {
		return TokensPair{}, err
	}
	if err := s.tokens.Rotate(ctx, refreshToken, tp.RefreshToken, tp.RefreshTokenExpiresAt); err != nil {
		return TokensPair{}, err
	}
	return tp, nil
}
