package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/t0mer/skryol/internal/db"
)

// SessionCookie is the name of the session cookie.
const SessionCookie = "skryol_session"

// ErrInvalidCredentials is returned on a failed login.
var ErrInvalidCredentials = errors.New("invalid username or password")

// Config carries auth settings.
type Config struct {
	Enabled       bool
	Username      string
	Password      string // bootstrap password (first run only)
	SessionSecret string
	GuardMetrics  bool
}

// Service implements optional authentication.
type Service struct {
	db     *db.DB
	cfg    Config
	signer *sessionSigner
	log    *slog.Logger
}

// NewService builds the auth service.
func NewService(database *db.DB, cfg Config, log *slog.Logger) *Service {
	if cfg.Username == "" {
		cfg.Username = "admin"
	}
	return &Service{db: database, cfg: cfg, signer: newSessionSigner(cfg.SessionSecret), log: log}
}

// Enabled reports whether authentication is required.
func (s *Service) Enabled() bool { return s.cfg.Enabled }

// GuardMetrics reports whether /metrics requires auth.
func (s *Service) GuardMetrics() bool { return s.cfg.GuardMetrics }

// Bootstrap ensures an admin account exists when auth is enabled. It uses the
// configured bootstrap password, or generates and logs a random one.
func (s *Service) Bootstrap(ctx context.Context) error {
	if !s.cfg.Enabled {
		return nil
	}
	n, err := s.db.CountUsers(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	password := s.cfg.Password
	generated := false
	if password == "" {
		buf := make([]byte, 12)
		if _, err := rand.Read(buf); err != nil {
			return err
		}
		password = hex.EncodeToString(buf)
		generated = true
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	if err := s.db.UpsertUser(ctx, s.cfg.Username, hash); err != nil {
		return err
	}
	if generated {
		s.log.Warn("created initial admin account with a generated password — change it via --reset-password",
			"username", s.cfg.Username, "password", password)
	} else {
		s.log.Info("created initial admin account", "username", s.cfg.Username)
	}
	return nil
}

// SetPassword sets the password for the admin user (used by --reset-password).
func (s *Service) SetPassword(ctx context.Context, password string) error {
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	return s.db.UpsertUser(ctx, s.cfg.Username, hash)
}

// Login verifies credentials and returns a signed session token.
func (s *Service) Login(ctx context.Context, username, password string) (string, error) {
	user, err := s.db.GetUserByUsername(ctx, username)
	if err != nil {
		return "", ErrInvalidCredentials
	}
	if !VerifyPassword(password, user.PasswordHash) {
		return "", ErrInvalidCredentials
	}
	return s.signer.mint(user.Username), nil
}

// Authenticate reports whether the request carries a valid session cookie or a
// valid bearer/API token. It always returns true when auth is disabled.
func (s *Service) Authenticate(r *http.Request) bool {
	if !s.cfg.Enabled {
		return true
	}
	// Session cookie.
	if c, err := r.Cookie(SessionCookie); err == nil {
		if _, ok := s.signer.verify(c.Value); ok {
			return true
		}
	}
	// Bearer / API token.
	token := strings.TrimSpace(r.Header.Get("X-API-Token"))
	if token == "" {
		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
			token = strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
		}
	}
	if token != "" {
		ok, err := s.db.TokenExists(r.Context(), HashToken(token))
		if err == nil && ok {
			return true
		}
	}
	return false
}

// CreateToken mints a new API token, returning the plaintext once.
func (s *Service) CreateToken(ctx context.Context, label string) (string, *db.APIToken, error) {
	token, hash, err := GenerateToken()
	if err != nil {
		return "", nil, err
	}
	rec, err := s.db.CreateToken(ctx, label, hash)
	if err != nil {
		return "", nil, err
	}
	return token, rec, nil
}

// ListTokens returns token metadata.
func (s *Service) ListTokens(ctx context.Context) ([]db.APIToken, error) {
	return s.db.ListTokens(ctx)
}

// DeleteToken revokes a token.
func (s *Service) DeleteToken(ctx context.Context, id string) error {
	return s.db.DeleteToken(ctx, id)
}
