package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	//"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/oauth2"
	"terminal/internal/session"
	"terminal/internal/user"
)

type Handlers struct {
	provider     *oidc.Provider
	oauth2Config *oauth2.Config
	verifier     *oidc.IDTokenVerifier
	userManager  UserManager
	sessionManager SessionManager
}

type UserManager interface {
	CreateUser(username, email string) (*user.User, error)
	GetUser(username string) (*user.User, error)
	SanitizeUsername(email string) string
	ValidateUsername(username string) error
	EnsureUserDirectory(username string) error
}

type SessionManager interface {
	CreateSession(username, email string) (*session.Session, error)
	ValidateToken(token string) (*session.Claims, error)
	GetCookieSettings() (string, bool, bool)
}

// Remove the Claims interface - use session.Claims instead

type OIDCConfig struct {
	ClientID     string
	ClientSecret string
	IssuerURL    string
	RedirectURL  string
	Scopes       []string
}

func NewHandlers(config OIDCConfig, userManager UserManager, sessionManager SessionManager) (*Handlers, error) {
	ctx := context.Background()
	
	provider, err := oidc.NewProvider(ctx, config.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: config.ClientID,
	})

	oauth2Config := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       config.Scopes,
	}

	return &Handlers{
		provider:     provider,
		oauth2Config: oauth2Config,
		verifier:     verifier,
		userManager:  userManager,
		sessionManager: sessionManager,
	}, nil
}

func (h *Handlers) Login(c *fiber.Ctx) error {
	// Generate random state
	state, err := generateRandomString(32)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to generate state",
		})
	}

	// Generate random nonce
	nonce, err := generateRandomString(32)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to generate nonce",
		})
	}

	// Store state and nonce in session (simplified - in production use proper session storage)
	c.Cookie(&fiber.Cookie{
		Name:     "oauth_state",
		Value:    state,
		HTTPOnly: true,
		Secure:   true,
		SameSite: "Lax",
		MaxAge:   600, // 10 minutes
	})

	c.Cookie(&fiber.Cookie{
		Name:     "oauth_nonce",
		Value:    nonce,
		HTTPOnly: true,
		Secure:   true,
		SameSite: "Lax",
		MaxAge:   600, // 10 minutes
	})

	// Redirect to OIDC provider
	url := h.oauth2Config.AuthCodeURL(state, oidc.Nonce(nonce))
	return c.Redirect(url, http.StatusFound)
}

func (h *Handlers) Callback(c *fiber.Ctx) error {
	// Get state and nonce from cookies
	state := c.Cookies("oauth_state")
	nonce := c.Cookies("oauth_nonce")
	
	if state == "" || nonce == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "missing state or nonce",
		})
	}

	// Clear cookies
	c.Cookie(&fiber.Cookie{
		Name:     "oauth_state",
		Value:    "",
		HTTPOnly: true,
		Secure:   true,
		SameSite: "Lax",
		MaxAge:   -1,
	})
	c.Cookie(&fiber.Cookie{
		Name:     "oauth_nonce",
		Value:    "",
		HTTPOnly: true,
		Secure:   true,
		SameSite: "Lax",
		MaxAge:   -1,
	})

	// Verify state
	if c.Query("state") != state {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid state",
		})
	}

	// Exchange code for token
	code := c.Query("code")
	if code == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "missing authorization code",
		})
	}

	ctx := context.Background()
	oauth2Token, err := h.oauth2Config.Exchange(ctx, code)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "failed to exchange token",
		})
	}

	// Extract ID token
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "missing id_token",
		})
	}

	// Verify ID token
	idToken, err := h.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "failed to verify id_token",
		})
	}

	// Verify nonce
	if idToken.Nonce != nonce {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid nonce",
		})
	}

	// Extract claims
	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to parse claims",
		})
	}

	// Validate email
	if claims.Email == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "email not provided",
		})
	}

	if !claims.EmailVerified {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "email not verified",
		})
	}

	// Determine username
	username := claims.PreferredUsername
	if username == "" {
		username = h.userManager.SanitizeUsername(claims.Email)
	}

	// Validate username
	if err := h.userManager.ValidateUsername(username); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Sprintf("invalid username: %v", err),
		})
	}

	// Create or get user
	user, err := h.userManager.CreateUser(username, claims.Email)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("failed to create user: %v", err),
		})
	}

	// Ensure user directory and setup environment
	if err := h.userManager.EnsureUserDirectory(username); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("failed to setup user directory: %v", err),
		})
	}
	// SetupUserEnvironment is no longer needed - useradd -m handles everything

	// Create session
	session, err := h.sessionManager.CreateSession(user.Username, claims.Email)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("failed to create session: %v", err),
		})
	}

	// Set session cookie
	cookieName, secure, httpOnly := h.sessionManager.GetCookieSettings()
	c.Cookie(&fiber.Cookie{
		Name:     cookieName,
		Value:    session.Token,
		HTTPOnly: httpOnly,
		Secure:   secure,
		SameSite: "Lax",
		MaxAge:   86400, // 24 hours
	})

	// Redirect to terminal
	return c.Redirect("/", http.StatusFound)
}

func (h *Handlers) Logout(c *fiber.Ctx) error {
	cookieName, _, _ := h.sessionManager.GetCookieSettings()
	
	// Clear session cookie
	c.Cookie(&fiber.Cookie{
		Name:     cookieName,
		Value:    "",
		HTTPOnly: true,
		Secure:   true,
		SameSite: "Lax",
		MaxAge:   -1,
	})

	return c.Redirect("/", http.StatusFound)
}

func (h *Handlers) UserInfo(c *fiber.Ctx) error {
	token := c.Cookies("session_token")
	if token == "" {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
			"error": "not authenticated",
		})
	}

	claims, err := h.sessionManager.ValidateToken(token)
	if err != nil {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
			"error": "invalid session",
		})
	}

	return c.JSON(fiber.Map{
		"username": claims.Username,
		"email":    claims.Email,
	})
}

func generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// Middleware to require authentication
func (h *Handlers) RequireAuth(c *fiber.Ctx) error {
	token := c.Cookies("session_token")
	if token == "" {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
			"error": "authentication required",
		})
	}

	claims, err := h.sessionManager.ValidateToken(token)
	if err != nil {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
			"error": "invalid session",
		})
	}

	// Store user info in context for later use
	c.Locals("username", claims.Username)
	c.Locals("email", claims.Email)
	
	return c.Next()
}