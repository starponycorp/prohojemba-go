package auth_test

import (
	"context"
	"errors"
	"fmt"
	"prohojemba-go/internal/app/auth"
	"prohojemba-go/internal/domain"
	"testing"
	"time"
)

type TestPasswordHasher struct {
}

func NewTestPasswordHasher() *TestPasswordHasher {
	return &TestPasswordHasher{}
}

func (h *TestPasswordHasher) Hash(password string) (string, error) {
	return "hash:" + password, nil
}

func (h *TestPasswordHasher) Verify(password string, hash string) bool {
	return "hash:"+password == hash
}

type TestTokensIssuer struct {
}

func NewTestTokenIssuer() *TestTokensIssuer {
	return &TestTokensIssuer{}
}

func (i *TestTokensIssuer) Issue(ctx context.Context, userId uint, accessTTL time.Duration, refreshTTL time.Duration) (auth.TokensPair, error) {
	now := time.Now()
	suffix := now.UnixNano()
	return auth.TokensPair{
		AccessToken:           "access-" + fmt.Sprintf("%d-%d", userId, suffix),
		RefreshToken:          "refresh-" + fmt.Sprintf("%d-%d", userId, suffix),
		AccessTokenExpiresAt:  now.Add(accessTTL),
		RefreshTokenExpiresAt: now.Add(refreshTTL),
	}, nil
}

type InMemoryUsersRepo struct {
	rows map[string]domain.User
}

func NewInMemoryUsersRepo() *InMemoryUsersRepo {
	return &InMemoryUsersRepo{rows: map[string]domain.User{
		"test-user": {Id: 1, Username: "test-user", HashedPassword: "hash:test-password"},
	}}
}

func (r *InMemoryUsersRepo) GetByUsername(ctx context.Context, username string) (domain.User, error) {
	//TODO implement me
	u, ok := r.rows[username]
	if !ok {
		return domain.User{}, auth.ErrUserNotFound
	}
	return u, nil
}

type InMemoryRefreshTokensRepo struct {
	rows map[string]struct {
		UserId    uint
		ExpiresAt time.Time
	}
}

func NewInMemoryRefreshTokensRepo() *InMemoryRefreshTokensRepo {
	return &InMemoryRefreshTokensRepo{rows: make(map[string]struct {
		UserId    uint
		ExpiresAt time.Time
	})}
}

func (r *InMemoryRefreshTokensRepo) Store(ctx context.Context, userId uint, token string, expiresAt time.Time) error {
	r.rows[token] = struct {
		UserId    uint
		ExpiresAt time.Time
	}{UserId: userId, ExpiresAt: expiresAt}
	return nil
}

func (r *InMemoryRefreshTokensRepo) Rotate(ctx context.Context, oldToken string, newToken string, newExpiresAt time.Time) error {
	row := r.rows[oldToken]
	delete(r.rows, oldToken)
	r.rows[newToken] = struct {
		UserId    uint
		ExpiresAt time.Time
	}{UserId: row.UserId, ExpiresAt: newExpiresAt}
	return nil
}

func (r *InMemoryRefreshTokensRepo) GetByToken(ctx context.Context, token string) (struct {
	UserId    uint
	ExpiresAt time.Time
}, error) {
	row, ok := r.rows[token]
	if !ok {
		return struct {
			UserId    uint
			ExpiresAt time.Time
		}{}, auth.ErrInvalidCredentials
	}
	return row, nil
}

func TestService_Login(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		usersRepo := NewInMemoryUsersRepo()
		tokensRepo := NewInMemoryRefreshTokensRepo()
		hasher := NewTestPasswordHasher()
		issuer := NewTestTokenIssuer()
		service := auth.NewService(usersRepo, tokensRepo, hasher, issuer, time.Minute, time.Hour)

		u, tp, err := service.Login(context.Background(), "test-user", "test-password")
		if err != nil {
			t.Errorf("Login returns err: %v", err)
			return
		}
		if u.Username != "test-user" {
			t.Errorf("Login returns user with wrong username, got %v, expected %v", u.Username, "test-user")
		}
		if tp.AccessToken == "" {
			t.Errorf("Login returns empty access token, got %v", tp)
		}
		if tp.RefreshToken == "" {
			t.Errorf("Login returns empty refresh token, got %v", tp)
		}
		if tp.AccessTokenExpiresAt.Before(time.Now()) {
			t.Errorf("Login returns access token expired, got %v", tp)
		}
		if tp.RefreshTokenExpiresAt.Before(time.Now()) {
			t.Errorf("Login returns refresh token expired, got %v", tp)
		}
	})
	t.Run("invalid username", func(t *testing.T) {
		usersRepo := NewInMemoryUsersRepo()
		tokensRepo := NewInMemoryRefreshTokensRepo()
		hasher := NewTestPasswordHasher()
		issuer := NewTestTokenIssuer()
		service := auth.NewService(usersRepo, tokensRepo, hasher, issuer, time.Minute, time.Hour)

		u, tp, err := service.Login(context.Background(), "invalid-user", "test-password")
		if !errors.Is(err, auth.ErrUserNotFound) {
			t.Errorf("Login returns invalid err: %v", err)
		}
		emptyUser := domain.User{}
		if u != emptyUser {
			t.Errorf("Login returns non empty user, got %v", u)
		}
		emptyTokens := auth.TokensPair{}
		if tp != emptyTokens {
			t.Errorf("Login returns non empty tokens, got %v", tp)
		}
	})
	t.Run("invalid password", func(t *testing.T) {
		usersRepo := NewInMemoryUsersRepo()
		tokensRepo := NewInMemoryRefreshTokensRepo()
		hasher := NewTestPasswordHasher()
		issuer := NewTestTokenIssuer()
		service := auth.NewService(usersRepo, tokensRepo, hasher, issuer, time.Minute, time.Hour)

		u, tp, err := service.Login(context.Background(), "test-user", "invalid-password")
		if !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("Login returns invalid err: %v", err)
		}
		emptyUser := domain.User{}
		if u != emptyUser {
			t.Errorf("Login returns non empty user, got %v", u)
		}
		emptyTokens := auth.TokensPair{}
		if tp != emptyTokens {
			t.Errorf("Login returns non empty tokens, got %v", tp)
		}
	})

}

func TestService_Close(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		usersRepo := NewInMemoryUsersRepo()
		tokensRepo := NewInMemoryRefreshTokensRepo()
		hasher := NewTestPasswordHasher()
		issuer := NewTestTokenIssuer()
		service := auth.NewService(usersRepo, tokensRepo, hasher, issuer, time.Minute, time.Hour)

		if err := tokensRepo.Store(context.Background(), 1, "test-token", time.Now().Add(time.Hour)); err != nil {
			t.Errorf("Storing refresh token for testing err: %v", err)
			return
		}
		tp, err := service.Refresh(context.Background(), "test-token")
		if err != nil {
			t.Errorf("Refresh returns err: %v", err)
			return
		}
		if tp.AccessToken == "" {
			t.Errorf("Refresh returns empty access token, got %v", tp)
		}
		if tp.RefreshToken == "" {
			t.Errorf("Refresh returns empty refresh token, got %v", tp)
		}
		if tp.AccessTokenExpiresAt.Before(time.Now()) {
			t.Errorf("Refresh returns access token expired, got %v", tp)
		}
		if tp.RefreshTokenExpiresAt.Before(time.Now()) {
			t.Errorf("Refresh returns refresh token expired, got %v", tp)
		}
	})
	t.Run("invalid refresh token", func(t *testing.T) {
		usersRepo := NewInMemoryUsersRepo()
		tokensRepo := NewInMemoryRefreshTokensRepo()
		hasher := NewTestPasswordHasher()
		issuer := NewTestTokenIssuer()
		service := auth.NewService(usersRepo, tokensRepo, hasher, issuer, time.Minute, time.Hour)

		tp, err := service.Refresh(context.Background(), "invalid-refresh-token")
		if !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("Login returns invalid err: %v", err)
		}
		emptyTokens := auth.TokensPair{}
		if tp != emptyTokens {
			t.Errorf("Login returns non empty tokens, got %v", tp)
		}
	})
	t.Run("expired refresh token", func(t *testing.T) {
		usersRepo := NewInMemoryUsersRepo()
		tokensRepo := NewInMemoryRefreshTokensRepo()
		hasher := NewTestPasswordHasher()
		issuer := NewTestTokenIssuer()
		service := auth.NewService(usersRepo, tokensRepo, hasher, issuer, time.Minute, time.Hour)

		if err := tokensRepo.Store(context.Background(), 1, "test-token", time.Now().Add(-time.Hour)); err != nil {
			t.Errorf("Storing refresh token for testing err: %v", err)
		}

		tp, err := service.Refresh(context.Background(), "test-token")
		if !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("Login returns invalid err: %v", err)
		}
		emptyTokens := auth.TokensPair{}
		if tp != emptyTokens {
			t.Errorf("Login returns non empty tokens, got %v", tp)
		}
	})
}
