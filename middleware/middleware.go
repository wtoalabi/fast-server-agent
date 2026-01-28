/**
 * Middleware Package
 *
 * Contains middleware components for the Server Agent.
 *
 * @package middleware
 */
package middleware

import (
	"crypto/subtle"
	"os"

	"github.com/gofiber/fiber/v2"
)

/**
 * AuthConfig holds configuration for the auth middleware.
 */
type AuthConfig struct {
	// Token is the expected API token
	Token string
	// TokenHeader is the header name for the token (default: X-Agent-Token)
	TokenHeader string
	// Skip is a function to determine if middleware should be skipped
	Skip func(*fiber.Ctx) bool
}

/**
 * DefaultAuthConfig returns the default auth middleware configuration.
 *
 * @return AuthConfig Default configuration
 */
func DefaultAuthConfig() AuthConfig {
	return AuthConfig{
		Token:       os.Getenv("AGENT_TOKEN"),
		TokenHeader: "X-Agent-Token",
		Skip:        nil,
	}
}

/**
 * Auth creates a new auth middleware with the given configuration.
 *
 * This middleware validates the API token sent in the request header.
 * Uses constant-time comparison to prevent timing attacks.
 *
 * @param config Auth configuration
 * @return fiber.Handler The middleware handler
 */
func Auth(config ...AuthConfig) fiber.Handler {
	cfg := DefaultAuthConfig()
	if len(config) > 0 {
		cfg = config[0]
		if cfg.TokenHeader == "" {
			cfg.TokenHeader = "X-Agent-Token"
		}
	}

	return func(c *fiber.Ctx) error {
		// Skip if configured
		if cfg.Skip != nil && cfg.Skip(c) {
			return c.Next()
		}

		// Get token from header
		token := c.Get(cfg.TokenHeader)
		if token == "" {
			return c.Status(401).JSON(fiber.Map{
				"success": false,
				"error":   "missing authentication token",
			})
		}

		// Constant-time comparison to prevent timing attacks
		if subtle.ConstantTimeCompare([]byte(token), []byte(cfg.Token)) != 1 {
			return c.Status(401).JSON(fiber.Map{
				"success": false,
				"error":   "invalid authentication token",
			})
		}

		return c.Next()
	}
}

/**
 * RateLimitConfig holds configuration for rate limiting.
 */
type RateLimitConfig struct {
	// Max requests per window
	Max int
	// Window duration in seconds
	WindowSeconds int
}

/**
 * IPWhitelist creates a middleware that only allows requests from whitelisted IPs.
 *
 * @param allowedIPs List of allowed IP addresses
 * @return fiber.Handler The middleware handler
 */
func IPWhitelist(allowedIPs []string) fiber.Handler {
	ipMap := make(map[string]bool)
	for _, ip := range allowedIPs {
		ipMap[ip] = true
	}

	return func(c *fiber.Ctx) error {
		clientIP := c.IP()

		// Always allow localhost
		if clientIP == "127.0.0.1" || clientIP == "::1" {
			return c.Next()
		}

		if !ipMap[clientIP] {
			return c.Status(403).JSON(fiber.Map{
				"success": false,
				"error":   "IP not allowed",
			})
		}

		return c.Next()
	}
}

/**
 * RequestLogger creates a middleware that logs requests.
 *
 * @return fiber.Handler The middleware handler
 */
func RequestLogger() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Log request (in a real implementation, use a proper logger)
		// fmt.Printf("[%s] %s %s\n", time.Now().Format("2006-01-02 15:04:05"), c.Method(), c.Path())
		return c.Next()
	}
}
