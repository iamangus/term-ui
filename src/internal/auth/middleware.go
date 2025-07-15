package auth

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
)

// SecurityHeaders adds security headers to all responses
func SecurityHeaders() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Security headers
		c.Set("X-Content-Type-Options", "nosniff")
		c.Set("X-Frame-Options", "DENY")
		c.Set("X-XSS-Protection", "1; mode=block")
		c.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		
		// CSP for terminal application
		csp := []string{
			"default-src 'self'",
			"script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
			"style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
			"font-src 'self' data:",
			"connect-src 'self' wss: ws:",
			"img-src 'self' data:",
			"object-src 'none'",
			"base-uri 'self'",
			"form-action 'self'",
		}
		c.Set("Content-Security-Policy", strings.Join(csp, "; "))
		
		return c.Next()
	}
}

// RateLimitMiddleware provides basic rate limiting
func RateLimitMiddleware(maxRequests int, window time.Duration) fiber.Handler {
	type client struct {
		requests int
		lastSeen time.Time
	}
	
	clients := make(map[string]*client)
	mu := sync.RWMutex{}
	
	return func(c *fiber.Ctx) error {
		ip := c.IP()
		
		mu.Lock()
		defer mu.Unlock()
		
		now := time.Now()
		
		// Clean old entries
		for key, client := range clients {
			if now.Sub(client.lastSeen) > window {
				delete(clients, key)
			}
		}
		
		// Check current client
		clientInfo, exists := clients[ip]
		if !exists {
			clients[ip] = &client{
				requests: 1,
				lastSeen: now,
			}
			return c.Next()
		}
		
		// Reset counter if window passed
		if now.Sub(clientInfo.lastSeen) > window {
			clientInfo.requests = 1
			clientInfo.lastSeen = now
			return c.Next()
		}
		
		// Check limit
		if clientInfo.requests >= maxRequests {
			return c.Status(http.StatusTooManyRequests).JSON(fiber.Map{
				"error": "rate limit exceeded",
			})
		}
		
		clientInfo.requests++
		clientInfo.lastSeen = now
		
		return c.Next()
	}
}

// CORSMiddleware handles CORS for API endpoints
func CORSMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		c.Set("Access-Control-Allow-Origin", "*")
		c.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization")
		
		if c.Method() == "OPTIONS" {
			return c.SendStatus(http.StatusOK)
		}
		
		return c.Next()
	}
}