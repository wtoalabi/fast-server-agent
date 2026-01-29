/**
 * Server Agent - Main Entry Point
 *
 * A lightweight daemon for ultra-fast server management.
 * Eliminates SSH overhead by running locally and accepting HTTP commands.
 *
 * Features:
 * - Command execution with timeout support
 * - File read/write with path whitelisting
 * - Service management (systemctl)
 * - System metrics collection
 * - WebSocket for real-time updates
 *
 * Security:
 * - Listens only on 127.0.0.1 by default
 * - API token authentication
 * - Path whitelisting for file operations
 * - Command validation
 *
 * Performance:
 * - 10-50ms response time (vs 500ms-2s for SSH)
 * - ~5MB memory usage
 * - Minimal CPU overhead
 *
 * @package server-agent
 * @version 1.0.1
 */
package main

import (
	"crypto/subtle"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/fast/server-agent/handlers"
	"github.com/fast/server-agent/systemd"
	"github.com/fast/server-agent/watchdog"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/websocket/v2"
)

// Version information - injected at build time via ldflags
// Build with: go build -ldflags "-X main.Version=1.0.1 -X main.BuildNumber=1 -X main.BuildDate=2026-01-28"
var (
	Version     = "dev"
	BuildNumber = "0"
	BuildDate   = "unknown"
)

// Config holds the agent configuration
type Config struct {
	// Port to listen on
	Port int
	// Host address (127.0.0.1 for local only, 0.0.0.0 for all interfaces)
	Host string
	// API token for authentication
	Token string
	// AllowedIPs is a comma-separated list of IPs allowed to connect
	// Empty means only token auth is required
	AllowedIPs string
	// Log file path
	LogFile string
	// Enable debug mode
	Debug bool
	// WatchdogEnabled enables SSH watchdog monitoring
	WatchdogEnabled bool
	// WatchdogInterval is seconds between watchdog checks
	WatchdogInterval int
}

// Global watchdog instance for API access
var sshWatchdog *watchdog.Watchdog

func main() {
	// Parse command line flags
	config := parseFlags()

	// Validate configuration
	if err := validateConfig(config); err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	// Setup logging
	setupLogging(config)

	// Start systemd notifier (for systemd watchdog support)
	sdNotifier := systemd.NewNotifier()
	if sdNotifier != nil {
		sdNotifier.Start()
		defer sdNotifier.Stop()
	}

	// Initialize and start SSH watchdog
	sshWatchdog = initWatchdog(config)
	if sshWatchdog != nil {
		sshWatchdog.Start()
		defer sshWatchdog.Stop()
	}

	// Create Fiber app
	app := createApp(config)

	// Register routes
	registerRoutes(app, config)

	// Handle graceful shutdown
	setupGracefulShutdown(app)

	// Start server
	addr := fmt.Sprintf("%s:%d", config.Host, config.Port)
	log.Printf("Server Agent v%s starting on %s", Version, addr)

	if err := app.Listen(addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

/**
 * parseFlags parses command line arguments.
 *
 * @return Config The parsed configuration
 */
func parseFlags() Config {
	config := Config{}

	// About flag to display agent info
	showAbout := flag.Bool("a", false, "Show about information")
	// Version flag to display just the version number
	showVersion := flag.Bool("v", false, "Show version number only")

	flag.IntVar(&config.Port, "port", 3456, "Port to listen on")
	flag.StringVar(&config.Host, "host", "127.0.0.1", "Host address to bind to")
	flag.StringVar(&config.Token, "token", "", "API token (overrides AGENT_TOKEN env)")
	flag.StringVar(&config.AllowedIPs, "allowed-ips", "", "Comma-separated list of allowed IPs")
	flag.StringVar(&config.LogFile, "log", "/var/log/server-agent.log", "Log file path")
	flag.BoolVar(&config.Debug, "debug", false, "Enable debug mode")
	flag.BoolVar(&config.WatchdogEnabled, "watchdog", true, "Enable SSH watchdog monitoring")
	flag.IntVar(&config.WatchdogInterval, "watchdog-interval", 30, "Seconds between watchdog checks")

	// Custom usage message
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Server Agent v%s\n\n", Version)
		fmt.Fprintf(os.Stderr, "A lightweight daemon for fast server management.\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nEnvironment Variables:\n")
		fmt.Fprintf(os.Stderr, "  AGENT_TOKEN            API token for authentication\n")
		fmt.Fprintf(os.Stderr, "  AGENT_ALLOWED_IPS      Comma-separated list of allowed IPs\n")
		fmt.Fprintf(os.Stderr, "  WATCHDOG_ENABLED       Enable SSH watchdog (true/false)\n")
		fmt.Fprintf(os.Stderr, "  WATCHDOG_INTERVAL      Seconds between watchdog checks\n")
	}

	flag.Parse()

	// Handle version flag - output version and build number (pipe-separated for parsing)
	if *showVersion {
		fmt.Printf("%s|%s\n", Version, BuildNumber)
		os.Exit(0)
	}

	// Handle about flag
	if *showAbout {
		printAbout()
		os.Exit(0)
	}

	// Token from env if not provided via flag
	if config.Token == "" {
		config.Token = os.Getenv("AGENT_TOKEN")
	}

	// AllowedIPs from env if not provided via flag
	if config.AllowedIPs == "" {
		config.AllowedIPs = os.Getenv("AGENT_ALLOWED_IPS")
	}

	// Watchdog settings from env
	if watchdogEnv := os.Getenv("WATCHDOG_ENABLED"); watchdogEnv != "" {
		config.WatchdogEnabled = watchdogEnv == "true" || watchdogEnv == "1"
	}

	return config
}

/**
 * initWatchdog initializes the SSH watchdog based on configuration.
 *
 * The watchdog monitors the SSH service and automatically restarts it
 * if it becomes unavailable. This prevents lockout scenarios when
 * managing SSH settings remotely through the agent.
 *
 * @param config The agent configuration
 * @return *watchdog.Watchdog The initialized watchdog, or nil if disabled
 */
func initWatchdog(config Config) *watchdog.Watchdog {
	if !config.WatchdogEnabled {
		log.Println("SSH Watchdog is disabled")
		return nil
	}

	cfg := watchdog.DefaultConfig()
	cfg.Enabled = true
	cfg.CheckInterval = time.Duration(config.WatchdogInterval) * time.Second

	log.Printf("SSH Watchdog enabled (check interval: %ds)", config.WatchdogInterval)
	return watchdog.New(cfg)
}

/**
 * GetWatchdog returns the global watchdog instance for API handlers.
 *
 * @return *watchdog.Watchdog The watchdog instance
 */
func GetWatchdog() *watchdog.Watchdog {
	return sshWatchdog
}

/**
 * validateConfig validates the agent configuration.
 *
 * @param config The configuration to validate
 * @return error Any validation error
 */
func validateConfig(config Config) error {
	if config.Token == "" {
		return fmt.Errorf("API token is required (use -token flag or AGENT_TOKEN env)")
	}

	if len(config.Token) < 32 {
		return fmt.Errorf("API token must be at least 32 characters")
	}

	if config.Port < 1 || config.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}

	return nil
}

/**
 * setupLogging configures the logging system.
 *
 * @param config The agent configuration
 */
func setupLogging(config Config) {
	// In production, log to file
	if !config.Debug && config.LogFile != "" {
		f, err := os.OpenFile(config.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Printf("Warning: Could not open log file %s: %v", config.LogFile, err)
		} else {
			log.SetOutput(f)
		}
	}

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
}

/**
 * parseAllowedIPs parses a comma-separated list of IP addresses.
 *
 * @param ipList Comma-separated list of IPs
 * @return []string Slice of trimmed IP addresses
 */
func parseAllowedIPs(ipList string) []string {
	if ipList == "" {
		return nil
	}
	
	var ips []string
	for _, ip := range strings.Split(ipList, ",") {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			ips = append(ips, ip)
		}
	}
	return ips
}

/**
 * createApp creates and configures the Fiber application.
 *
 * @param config The agent configuration
 * @return *fiber.App The configured Fiber app
 */
func createApp(config Config) *fiber.App {
	app := fiber.New(fiber.Config{
		DisableStartupMessage: !config.Debug,
		ServerHeader:          "Fast-Server-Agent",
		AppName:               "Server Agent v" + Version,
		ReadTimeout:           30 * time.Second,
		WriteTimeout:          30 * time.Second,
		IdleTimeout:           120 * time.Second,
		BodyLimit:             10 * 1024 * 1024, // 10MB
	})

	// Recovery middleware
	app.Use(recover.New(recover.Config{
		EnableStackTrace: config.Debug,
	}))

	// Logging middleware
	if config.Debug {
		app.Use(logger.New(logger.Config{
			Format:     "${time} | ${status} | ${latency} | ${method} ${path}\n",
			TimeFormat: "2006-01-02 15:04:05",
		}))
	}

	return app
}

/**
 * registerRoutes registers all API routes.
 *
 * @param app The Fiber application
 * @param config The agent configuration
 */
func registerRoutes(app *fiber.App, config Config) {
	// IP whitelist middleware (only if AllowedIPs is set)
	// This provides an additional layer of security when binding to 0.0.0.0
	var ipWhitelistMiddleware fiber.Handler
	if config.AllowedIPs != "" {
		allowedIPs := parseAllowedIPs(config.AllowedIPs)
		log.Printf("IP whitelist enabled: %v", allowedIPs)
		ipWhitelistMiddleware = func(c *fiber.Ctx) error {
			clientIP := c.IP()
			// Always allow localhost
			if clientIP == "127.0.0.1" || clientIP == "::1" {
				return c.Next()
			}
			// Check if client IP is in allowed list
			for _, ip := range allowedIPs {
				if clientIP == ip {
					return c.Next()
				}
			}
			log.Printf("Blocked request from unauthorized IP: %s", clientIP)
			return c.Status(403).JSON(fiber.Map{
				"success": false,
				"error":   "IP not allowed",
			})
		}
	}

	// Auth middleware function
	authMiddleware := func(c *fiber.Ctx) error {
		token := c.Get("X-Agent-Token")
		if subtle.ConstantTimeCompare([]byte(token), []byte(config.Token)) != 1 {
			return c.Status(401).JSON(fiber.Map{
				"success": false,
				"error":   "unauthorized",
			})
		}
		return c.Next()
	}

	// Public routes (no auth)
	app.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"name":    "Server Agent",
			"version": Version,
			"status":  "running",
		})
	})

	// API routes (with auth, and IP whitelist if configured)
	var api fiber.Router
	if ipWhitelistMiddleware != nil {
		api = app.Group("/api", ipWhitelistMiddleware, authMiddleware)
	} else {
		api = app.Group("/api", authMiddleware)
	}

	// Health & Status
	api.Get("/health", handlers.HealthCheck)
	api.Get("/info", handlers.SystemInfo)
	api.Get("/metrics", handlers.GetMetrics)

	// Command Execution
	api.Post("/exec", handlers.ExecuteCommand)
	api.Post("/exec/batch", handlers.ExecuteBatch)

	// File Operations
	api.Post("/file/read", handlers.ReadFile)
	api.Post("/file/write", handlers.WriteFile)
	api.Post("/file/exists", handlers.FileExists)
	api.Post("/file/stat", handlers.FileStat)

	// Service Management
	api.Get("/service/:name/status", handlers.ServiceStatus)
	api.Post("/service/:name/start", handlers.ServiceStart)
	api.Post("/service/:name/stop", handlers.ServiceStop)
	api.Post("/service/:name/restart", handlers.ServiceRestart)
	api.Post("/service/:name/enable", handlers.ServiceEnable)
	api.Post("/service/:name/disable", handlers.ServiceDisable)

	// Package Management (Basic)
	api.Get("/packages/updates", handlers.CheckUpdates)
	api.Post("/packages/install", handlers.InstallPackage)
	api.Post("/packages/remove", handlers.RemovePackage)

	// Package Management (Detailed - for Updates feature)
	api.Get("/updates/check", handlers.CheckUpdatesDetailed)
	api.Post("/updates/apply", handlers.ApplyUpdates)
	api.Get("/updates/reboot-required", handlers.RebootRequired)
	api.Post("/updates/reboot", handlers.ScheduleReboot)
	api.Delete("/updates/reboot", handlers.CancelReboot)
	api.Get("/updates/changelog", handlers.GetChangelog)
	api.Get("/updates/security", handlers.GetSecurityUpdates)

	// SSH Key Management
	api.Get("/ssh/keys", handlers.ListSSHKeys)
	api.Post("/ssh/keys", handlers.AddSSHKey)
	api.Delete("/ssh/keys/:fingerprint", handlers.RemoveSSHKey)

	// Watchdog Status
	api.Get("/watchdog/status", func(c *fiber.Ctx) error {
		w := GetWatchdog()
		if w == nil {
			return c.JSON(fiber.Map{
				"success": true,
				"enabled": false,
				"message": "SSH Watchdog is disabled",
			})
		}
		return c.JSON(fiber.Map{
			"success":  true,
			"enabled":  true,
			"services": w.GetStatus(),
		})
	})

	// WebSocket for real-time updates
	app.Use("/ws", func(c *fiber.Ctx) error {
		// Validate token from query param
		token := c.Query("token")
		if subtle.ConstantTimeCompare([]byte(token), []byte(config.Token)) != 1 {
			return c.Status(401).JSON(fiber.Map{"error": "unauthorized"})
		}

		if websocket.IsWebSocketUpgrade(c) {
			return c.Next()
		}
		return fiber.ErrUpgradeRequired
	})

	app.Get("/ws", websocket.New(handlers.WebSocketHandler))
}

/**
 * setupGracefulShutdown handles graceful shutdown on SIGINT/SIGTERM.
 *
 * @param app The Fiber application
 */
func setupGracefulShutdown(app *fiber.App) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		log.Println("Graceful shutdown initiated...")

		if err := app.Shutdown(); err != nil {
			log.Printf("Error during shutdown: %v", err)
		}
	}()
}

/**
 * printAbout displays information about the server agent.
 *
 * Prints version, description, features, and usage information
 * to help users understand the agent's capabilities.
 */
func printAbout() {
	about := `
╔═══════════════════════════════════════════════════════════════════╗
║                      FAST SERVER AGENT                            ║
╚═══════════════════════════════════════════════════════════════════╝

Version: %s
Build:   %s

DESCRIPTION
  A lightweight, high-performance server management daemon written in Go.
  Eliminates SSH overhead by running locally and accepting HTTP commands,
  providing ultra-fast response times for server management operations.

FEATURES
  Health & Status:
    • Health Check         - Agent health status and uptime
    • System Info          - Detailed OS, CPU, memory, disk information
    • System Metrics       - Real-time CPU, memory, disk, network stats
  
  Command Execution:
    • Execute Command      - Run shell commands with timeout support
    • Batch Execution      - Run multiple commands in sequence
    • Sudo Support         - Execute commands with elevated privileges
  
  File Operations:
    • Read File            - Read file contents with path whitelisting
    • Write File           - Write/create files securely
    • File Exists          - Check file existence
    • File Stats           - Get file metadata (size, permissions, dates)
  
  Service Management:
    • Service Status       - Check systemd service status
    • Start/Stop/Restart   - Control service lifecycle
    • Enable/Disable       - Manage service auto-start
    • Supports 20+ common services (nginx, mysql, php-fpm, etc.)
  
  Package Management:
    • Check Updates        - List available system updates
    • Detailed Updates     - Comprehensive update info with versions
    • Security Updates     - List security-specific updates
    • Apply Updates        - Install/upgrade packages
    • Install/Remove       - Package installation and removal
    • Changelog            - View package changelog
    • Reboot Management    - Schedule/cancel reboots
    • Supports apt, yum, and dnf package managers
  
  SSH Key Management:
    • List SSH Keys        - View authorized SSH keys per user
    • Add SSH Key          - Add new SSH keys securely
    • Remove SSH Key       - Delete SSH keys
  
  Safety & Reliability:
    • SSH Watchdog         - Auto-recovery for SSH service failures
    • Systemd Integration  - Native systemd watchdog support
    • WebSocket Support    - Real-time command output streaming

PERFORMANCE
  • Response Time: 10-50ms (vs 500ms-2s for SSH)
  • Memory Usage:  ~5MB RAM
  • CPU Overhead:  Minimal
  • Concurrent requests supported

SECURITY
  • Localhost-only binding by default (127.0.0.1)
  • API token authentication required (X-API-Token header)
  • Path whitelisting for file operations
  • Service whitelisting for systemctl operations
  • Command validation and sanitization
  • No root privileges required (uses sudo when needed)

USAGE
  server-agent [flags]

FLAGS
  -a                         Show this about information
  -port int                  Port to listen on (default 3456)
  -host string               Host address to bind to (default "127.0.0.1")
  -token string              API token for authentication
  -watchdog                  Enable SSH watchdog monitoring (default true)
  -watchdog-interval int     Seconds between watchdog checks (default 30)
  -log string                Log file path (default "/var/log/server-agent.log")
  -debug                     Enable debug mode

ENVIRONMENT VARIABLES
  AGENT_TOKEN               API token (alternative to -token flag)
  WATCHDOG_ENABLED          Enable SSH watchdog (true/false)
  WATCHDOG_INTERVAL         Seconds between watchdog checks

For more information, visit: https://github.com/fast/server-agent
`
	fmt.Printf(about, Version, BuildDate)
}
