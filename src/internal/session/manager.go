package session

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Claims struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	jwt.RegisteredClaims
}

type Manager struct {
	secret     []byte
	maxAge     time.Duration
	secure     bool
	httpOnly   bool
}

type Session struct {
	Token    string
	Username string
	Email    string
	Expiry   time.Time
}

func NewManager(secret string, maxAge int, secure, httpOnly bool) *Manager {
	return &Manager{
		secret:     []byte(secret),
		maxAge:     time.Duration(maxAge) * time.Second,
		secure:     secure,
		httpOnly:   httpOnly,
	}
}

func (m *Manager) CreateSession(username, email string) (*Session, error) {
	sessionID := uuid.New().String()
	
	claims := &Claims{
		Username: username,
		Email:    email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(m.maxAge)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ID:        sessionID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(m.secret)
	if err != nil {
		return nil, fmt.Errorf("failed to sign token: %w", err)
	}

	return &Session{
		Token:    signedToken,
		Username: username,
		Email:    email,
		Expiry:   claims.ExpiresAt.Time,
	}, nil
}

func (m *Manager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.secret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

func (m *Manager) RefreshToken(tokenString string) (*Session, error) {
	claims, err := m.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	// Create new session with same user info
	return m.CreateSession(claims.Username, claims.Email)
}

func (m *Manager) GetCookieSettings() (string, bool, bool) {
	return "session_token", m.secure, m.httpOnly
}

func (m *Manager) GetMaxAge() int {
	return int(m.maxAge.Seconds())
}