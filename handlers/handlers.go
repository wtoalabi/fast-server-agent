/**
 * Handlers Package
 *
 * Contains all HTTP request handlers for the Server Agent API.
 * Each handler implements a specific functionality for server management.
 *
 * @package handlers
 */
package handlers

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/websocket/v2"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

// Default command timeout
const DefaultTimeout = 30 * time.Second

// AllowedPaths defines whitelist of paths that can be read/written
var AllowedPaths = []string{
	"/etc/ssh/",
	"/etc/fail2ban/",
	"/etc/ufw/",
	"/etc/nginx/",
	"/etc/apache2/",
	"/etc/mysql/",
	"/etc/postgresql/",
	"/etc/php/",
	"/etc/redis/",
	"/etc/supervisor/",
	"/etc/crontab",
	"/var/log/",
	"/home/",
	"/var/www/",
	"/opt/",
}

// AllowedServices defines whitelist of services that can be managed
var AllowedServices = []string{
	"ssh", "sshd",
	"nginx", "apache2", "httpd",
	"mysql", "mariadb", "postgresql", "redis-server", "redis",
	"php-fpm", "php7.4-fpm", "php8.0-fpm", "php8.1-fpm", "php8.2-fpm", "php8.3-fpm",
	"supervisor", "supervisord",
	"fail2ban", "ufw",
	"cron",
	"docker",
	"memcached",
	"elasticsearch",
	"mongodb",
	"rabbitmq-server",
}

// =============================================================================
// HEALTH & STATUS HANDLERS
// =============================================================================

/**
 * HealthCheck returns the agent health status.
 *
 * @param c Fiber context
 * @return error
 */
func HealthCheck(c *fiber.Ctx) error {
	uptime, _ := host.Uptime()

	return c.JSON(fiber.Map{
		"success":     true,
		"status":      "healthy",
		"version":     "1.0.0",
		"uptime":      uptime,
		"timestamp":   time.Now().Unix(),
		"go_version":  runtime.Version(),
		"go_routines": runtime.NumGoroutine(),
	})
}

/**
 * SystemInfo returns detailed system information.
 *
 * @param c Fiber context
 * @return error
 */
func SystemInfo(c *fiber.Ctx) error {
	hostInfo, err := host.Info()
	if err != nil {
		return errorResponse(c, 500, "Failed to get host info: "+err.Error())
	}

	cpuInfo, _ := cpu.Info()
	memInfo, _ := mem.VirtualMemory()
	diskInfo, _ := disk.Usage("/")

	return c.JSON(fiber.Map{
		"success": true,
		"data": fiber.Map{
			"hostname":         hostInfo.Hostname,
			"os":               hostInfo.OS,
			"platform":         hostInfo.Platform,
			"platform_family":  hostInfo.PlatformFamily,
			"platform_version": hostInfo.PlatformVersion,
			"kernel_version":   hostInfo.KernelVersion,
			"kernel_arch":      hostInfo.KernelArch,
			"uptime":           hostInfo.Uptime,
			"boot_time":        hostInfo.BootTime,
			"cpu": fiber.Map{
				"cores":      len(cpuInfo),
				"model":      firstOrEmpty(cpuInfo).ModelName,
				"vendor":     firstOrEmpty(cpuInfo).VendorID,
				"cache_size": firstOrEmpty(cpuInfo).CacheSize,
			},
			"memory": fiber.Map{
				"total":        memInfo.Total,
				"available":    memInfo.Available,
				"used":         memInfo.Used,
				"used_percent": memInfo.UsedPercent,
			},
			"disk": fiber.Map{
				"total":        diskInfo.Total,
				"free":         diskInfo.Free,
				"used":         diskInfo.Used,
				"used_percent": diskInfo.UsedPercent,
			},
		},
	})
}

/**
 * GetMetrics returns current system metrics.
 *
 * @param c Fiber context
 * @return error
 */
func GetMetrics(c *fiber.Ctx) error {
	// CPU usage (1 second sample)
	cpuPercent, _ := cpu.Percent(time.Second, false)

	// Load average
	loadAvg, _ := load.Avg()

	// Memory
	memInfo, _ := mem.VirtualMemory()

	// Disk
	diskInfo, _ := disk.Usage("/")

	// Network I/O
	netIO, _ := net.IOCounters(false)

	var netStats fiber.Map
	if len(netIO) > 0 {
		netStats = fiber.Map{
			"bytes_sent":   netIO[0].BytesSent,
			"bytes_recv":   netIO[0].BytesRecv,
			"packets_sent": netIO[0].PacketsSent,
			"packets_recv": netIO[0].PacketsRecv,
		}
	}

	return c.JSON(fiber.Map{
		"success":   true,
		"timestamp": time.Now().Unix(),
		"metrics": fiber.Map{
			"cpu": fiber.Map{
				"percent":  firstFloat(cpuPercent),
				"load_1":   loadAvg.Load1,
				"load_5":   loadAvg.Load5,
				"load_15":  loadAvg.Load15,
			},
			"memory": fiber.Map{
				"total":        memInfo.Total,
				"available":    memInfo.Available,
				"used":         memInfo.Used,
				"used_percent": memInfo.UsedPercent,
				"swap_total":   memInfo.SwapTotal,
				"swap_used":    memInfo.SwapTotal - memInfo.SwapFree,
			},
			"disk": fiber.Map{
				"total":        diskInfo.Total,
				"free":         diskInfo.Free,
				"used":         diskInfo.Used,
				"used_percent": diskInfo.UsedPercent,
			},
			"network": netStats,
		},
	})
}

// =============================================================================
// COMMAND EXECUTION HANDLERS
// =============================================================================

// ExecRequest represents a command execution request
type ExecRequest struct {
	Command string `json:"command"`
	Timeout int    `json:"timeout"` // Timeout in seconds (default: 30)
	Sudo    bool   `json:"sudo"`    // Whether to run with sudo
}

// BatchExecRequest represents a batch command execution request
type BatchExecRequest struct {
	Commands    []string `json:"commands"`
	Timeout     int      `json:"timeout"`      // Timeout per command
	StopOnError bool     `json:"stop_on_error"` // Stop on first error
}

/**
 * ExecuteCommand executes a single command on the server.
 *
 * @param c Fiber context
 * @return error
 */
func ExecuteCommand(c *fiber.Ctx) error {
	var req ExecRequest
	if err := c.BodyParser(&req); err != nil {
		return errorResponse(c, 400, "Invalid request body")
	}

	if req.Command == "" {
		return errorResponse(c, 400, "Command is required")
	}

	timeout := DefaultTimeout
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout) * time.Second
	}

	// Prepare command
	command := req.Command
	if req.Sudo {
		command = "sudo " + command
	}

	result := executeWithTimeout(command, timeout)

	return c.JSON(fiber.Map{
		"success":     result.Success,
		"output":      result.Output,
		"exit_code":   result.ExitCode,
		"duration_ms": result.DurationMs,
	})
}

/**
 * ExecuteBatch executes multiple commands in sequence.
 *
 * @param c Fiber context
 * @return error
 */
func ExecuteBatch(c *fiber.Ctx) error {
	var req BatchExecRequest
	if err := c.BodyParser(&req); err != nil {
		return errorResponse(c, 400, "Invalid request body")
	}

	if len(req.Commands) == 0 {
		return errorResponse(c, 400, "At least one command is required")
	}

	timeout := DefaultTimeout
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout) * time.Second
	}

	results := make([]fiber.Map, 0, len(req.Commands))
	allSuccess := true

	for _, cmd := range req.Commands {
		result := executeWithTimeout(cmd, timeout)

		results = append(results, fiber.Map{
			"command":     cmd,
			"success":     result.Success,
			"output":      result.Output,
			"exit_code":   result.ExitCode,
			"duration_ms": result.DurationMs,
		})

		if !result.Success {
			allSuccess = false
			if req.StopOnError {
				break
			}
		}
	}

	return c.JSON(fiber.Map{
		"success": allSuccess,
		"results": results,
	})
}

// CommandResult holds the result of a command execution
type CommandResult struct {
	Success    bool
	Output     string
	ExitCode   int
	DurationMs int64
}

/**
 * executeWithTimeout executes a command with a timeout.
 *
 * @param command The command to execute
 * @param timeout The timeout duration
 * @return CommandResult
 */
func executeWithTimeout(command string, timeout time.Duration) CommandResult {
	startTime := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "bash", "-c", command)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	duration := time.Since(startTime).Milliseconds()

	output := stdout.String()
	if stderr.Len() > 0 {
		if output != "" {
			output += "\n"
		}
		output += stderr.String()
	}

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else if ctx.Err() == context.DeadlineExceeded {
			return CommandResult{
				Success:    false,
				Output:     "Command timed out after " + timeout.String(),
				ExitCode:   124, // Timeout exit code
				DurationMs: duration,
			}
		} else {
			exitCode = -1
		}
	}

	return CommandResult{
		Success:    exitCode == 0,
		Output:     strings.TrimSpace(output),
		ExitCode:   exitCode,
		DurationMs: duration,
	}
}

// =============================================================================
// FILE OPERATION HANDLERS
// =============================================================================

// FileRequest represents a file operation request
type FileRequest struct {
	Path    string `json:"path"`
	Content string `json:"content,omitempty"` // For write operations
	Sudo    bool   `json:"sudo"`
}

/**
 * ReadFile reads a file from the server.
 *
 * @param c Fiber context
 * @return error
 */
func ReadFile(c *fiber.Ctx) error {
	var req FileRequest
	if err := c.BodyParser(&req); err != nil {
		return errorResponse(c, 400, "Invalid request body")
	}

	if req.Path == "" {
		return errorResponse(c, 400, "Path is required")
	}

	if !isAllowedPath(req.Path) {
		return errorResponse(c, 403, "Access to this path is forbidden")
	}

	var content []byte
	var err error

	if req.Sudo {
		// Use sudo cat for restricted files
		result := executeWithTimeout("sudo cat "+req.Path, DefaultTimeout)
		if !result.Success {
			return errorResponse(c, 500, "Failed to read file: "+result.Output)
		}
		content = []byte(result.Output)
	} else {
		content, err = os.ReadFile(req.Path)
		if err != nil {
			return errorResponse(c, 500, "Failed to read file: "+err.Error())
		}
	}

	return c.JSON(fiber.Map{
		"success": true,
		"path":    req.Path,
		"content": string(content),
		"size":    len(content),
	})
}

/**
 * WriteFile writes content to a file.
 *
 * @param c Fiber context
 * @return error
 */
func WriteFile(c *fiber.Ctx) error {
	var req FileRequest
	if err := c.BodyParser(&req); err != nil {
		return errorResponse(c, 400, "Invalid request body")
	}

	if req.Path == "" {
		return errorResponse(c, 400, "Path is required")
	}

	if !isAllowedPath(req.Path) {
		return errorResponse(c, 403, "Access to this path is forbidden")
	}

	if req.Sudo {
		// Use sudo tee for restricted files
		cmd := fmt.Sprintf("echo '%s' | sudo tee %s > /dev/null", 
			strings.ReplaceAll(req.Content, "'", "'\\''"),
			req.Path)
		result := executeWithTimeout(cmd, DefaultTimeout)
		if !result.Success {
			return errorResponse(c, 500, "Failed to write file: "+result.Output)
		}
	} else {
		err := os.WriteFile(req.Path, []byte(req.Content), 0644)
		if err != nil {
			return errorResponse(c, 500, "Failed to write file: "+err.Error())
		}
	}

	return c.JSON(fiber.Map{
		"success": true,
		"path":    req.Path,
		"size":    len(req.Content),
	})
}

/**
 * FileExists checks if a file exists.
 *
 * @param c Fiber context
 * @return error
 */
func FileExists(c *fiber.Ctx) error {
	var req FileRequest
	if err := c.BodyParser(&req); err != nil {
		return errorResponse(c, 400, "Invalid request body")
	}

	if req.Path == "" {
		return errorResponse(c, 400, "Path is required")
	}

	_, err := os.Stat(req.Path)
	exists := !os.IsNotExist(err)

	return c.JSON(fiber.Map{
		"success": true,
		"path":    req.Path,
		"exists":  exists,
	})
}

/**
 * FileStat returns file information.
 *
 * @param c Fiber context
 * @return error
 */
func FileStat(c *fiber.Ctx) error {
	var req FileRequest
	if err := c.BodyParser(&req); err != nil {
		return errorResponse(c, 400, "Invalid request body")
	}

	if req.Path == "" {
		return errorResponse(c, 400, "Path is required")
	}

	info, err := os.Stat(req.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return c.JSON(fiber.Map{
				"success": true,
				"path":    req.Path,
				"exists":  false,
			})
		}
		return errorResponse(c, 500, "Failed to stat file: "+err.Error())
	}

	return c.JSON(fiber.Map{
		"success": true,
		"path":    req.Path,
		"exists":  true,
		"info": fiber.Map{
			"name":     info.Name(),
			"size":     info.Size(),
			"mode":     info.Mode().String(),
			"mod_time": info.ModTime().Unix(),
			"is_dir":   info.IsDir(),
		},
	})
}

// =============================================================================
// SERVICE MANAGEMENT HANDLERS
// =============================================================================

/**
 * ServiceStatus returns the status of a systemd service.
 *
 * @param c Fiber context
 * @return error
 */
func ServiceStatus(c *fiber.Ctx) error {
	name := c.Params("name")
	if !isAllowedService(name) {
		return errorResponse(c, 403, "Service not allowed")
	}

	// Get active status
	activeResult := executeWithTimeout(fmt.Sprintf("systemctl is-active %s", name), 5*time.Second)
	active := strings.TrimSpace(activeResult.Output) == "active"

	// Get enabled status
	enabledResult := executeWithTimeout(fmt.Sprintf("systemctl is-enabled %s", name), 5*time.Second)
	enabled := strings.TrimSpace(enabledResult.Output) == "enabled"

	return c.JSON(fiber.Map{
		"success": true,
		"service": name,
		"active":  active,
		"enabled": enabled,
		"status":  strings.TrimSpace(activeResult.Output),
	})
}

/**
 * ServiceStart starts a systemd service.
 *
 * @param c Fiber context
 * @return error
 */
func ServiceStart(c *fiber.Ctx) error {
	return serviceAction(c, "start")
}

/**
 * ServiceStop stops a systemd service.
 *
 * @param c Fiber context
 * @return error
 */
func ServiceStop(c *fiber.Ctx) error {
	return serviceAction(c, "stop")
}

/**
 * ServiceRestart restarts a systemd service.
 *
 * @param c Fiber context
 * @return error
 */
func ServiceRestart(c *fiber.Ctx) error {
	return serviceAction(c, "restart")
}

/**
 * ServiceEnable enables a systemd service.
 *
 * @param c Fiber context
 * @return error
 */
func ServiceEnable(c *fiber.Ctx) error {
	return serviceAction(c, "enable")
}

/**
 * ServiceDisable disables a systemd service.
 *
 * @param c Fiber context
 * @return error
 */
func ServiceDisable(c *fiber.Ctx) error {
	return serviceAction(c, "disable")
}

/**
 * serviceAction performs a systemctl action on a service.
 *
 * @param c Fiber context
 * @param action The systemctl action
 * @return error
 */
func serviceAction(c *fiber.Ctx, action string) error {
	name := c.Params("name")
	if !isAllowedService(name) {
		return errorResponse(c, 403, "Service not allowed")
	}

	result := executeWithTimeout(fmt.Sprintf("sudo systemctl %s %s", action, name), 30*time.Second)

	return c.JSON(fiber.Map{
		"success":     result.Success,
		"service":     name,
		"action":      action,
		"output":      result.Output,
		"duration_ms": result.DurationMs,
	})
}

// =============================================================================
// PACKAGE MANAGEMENT HANDLERS
// =============================================================================

/**
 * CheckUpdates checks for available package updates.
 *
 * @param c Fiber context
 * @return error
 */
func CheckUpdates(c *fiber.Ctx) error {
	// Update package lists
	executeWithTimeout("sudo apt-get update -qq", 60*time.Second)

	// Get upgradable packages
	result := executeWithTimeout("apt list --upgradable 2>/dev/null | tail -n +2", 30*time.Second)

	packages := []string{}
	if result.Success && result.Output != "" {
		lines := strings.Split(result.Output, "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) != "" {
				packages = append(packages, line)
			}
		}
	}

	return c.JSON(fiber.Map{
		"success":  true,
		"count":    len(packages),
		"packages": packages,
	})
}

// PackageRequest represents a package operation request
type PackageRequest struct {
	Package string `json:"package"`
}

/**
 * InstallPackage installs a package.
 *
 * @param c Fiber context
 * @return error
 */
func InstallPackage(c *fiber.Ctx) error {
	var req PackageRequest
	if err := c.BodyParser(&req); err != nil {
		return errorResponse(c, 400, "Invalid request body")
	}

	if req.Package == "" {
		return errorResponse(c, 400, "Package name is required")
	}

	result := executeWithTimeout(
		fmt.Sprintf("sudo DEBIAN_FRONTEND=noninteractive apt-get install -y %s", req.Package),
		300*time.Second,
	)

	return c.JSON(fiber.Map{
		"success":     result.Success,
		"package":     req.Package,
		"output":      result.Output,
		"duration_ms": result.DurationMs,
	})
}

/**
 * RemovePackage removes a package.
 *
 * @param c Fiber context
 * @return error
 */
func RemovePackage(c *fiber.Ctx) error {
	var req PackageRequest
	if err := c.BodyParser(&req); err != nil {
		return errorResponse(c, 400, "Invalid request body")
	}

	if req.Package == "" {
		return errorResponse(c, 400, "Package name is required")
	}

	result := executeWithTimeout(
		fmt.Sprintf("sudo DEBIAN_FRONTEND=noninteractive apt-get remove -y %s", req.Package),
		120*time.Second,
	)

	return c.JSON(fiber.Map{
		"success":     result.Success,
		"package":     req.Package,
		"output":      result.Output,
		"duration_ms": result.DurationMs,
	})
}

// =============================================================================
// SSH KEY MANAGEMENT HANDLERS
// =============================================================================

// SSHKeyRequest represents an SSH key operation request
type SSHKeyRequest struct {
	Username string `json:"username"`
	Key      string `json:"key"`       // For add operations
	Name     string `json:"name"`      // Key identifier
}

/**
 * ListSSHKeys lists SSH keys in authorized_keys.
 *
 * @param c Fiber context
 * @return error
 */
func ListSSHKeys(c *fiber.Ctx) error {
	username := c.Query("username", "root")
	
	homeDir := "/root"
	if username != "root" {
		homeDir = "/home/" + username
	}

	authKeysPath := homeDir + "/.ssh/authorized_keys"
	content, err := os.ReadFile(authKeysPath)
	if err != nil {
		if os.IsNotExist(err) {
			return c.JSON(fiber.Map{
				"success": true,
				"keys":    []string{},
			})
		}
		return errorResponse(c, 500, "Failed to read authorized_keys: "+err.Error())
	}

	keys := []fiber.Map{}
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			parts := strings.Fields(line)
			key := fiber.Map{
				"type": "",
				"key":  line,
				"name": "",
			}
			if len(parts) >= 1 {
				key["type"] = parts[0]
			}
			if len(parts) >= 3 {
				key["name"] = parts[2]
			}
			keys = append(keys, key)
		}
	}

	return c.JSON(fiber.Map{
		"success":  true,
		"username": username,
		"keys":     keys,
	})
}

/**
 * AddSSHKey adds an SSH key to authorized_keys.
 *
 * @param c Fiber context
 * @return error
 */
func AddSSHKey(c *fiber.Ctx) error {
	var req SSHKeyRequest
	if err := c.BodyParser(&req); err != nil {
		return errorResponse(c, 400, "Invalid request body")
	}

	if req.Key == "" {
		return errorResponse(c, 400, "Key is required")
	}

	username := req.Username
	if username == "" {
		username = "root"
	}

	homeDir := "/root"
	if username != "root" {
		homeDir = "/home/" + username
	}

	// Ensure .ssh directory exists
	sshDir := homeDir + "/.ssh"
	authKeysPath := sshDir + "/authorized_keys"

	commands := []string{
		fmt.Sprintf("mkdir -p %s", sshDir),
		fmt.Sprintf("chmod 700 %s", sshDir),
		fmt.Sprintf("touch %s", authKeysPath),
		fmt.Sprintf("chmod 600 %s", authKeysPath),
		fmt.Sprintf("grep -qxF '%s' %s || echo '%s' >> %s",
			req.Key, authKeysPath, req.Key, authKeysPath),
	}

	if username != "root" {
		commands = append(commands, fmt.Sprintf("chown -R %s:%s %s", username, username, sshDir))
	}

	for _, cmd := range commands {
		result := executeWithTimeout("sudo "+cmd, 10*time.Second)
		if !result.Success {
			return errorResponse(c, 500, "Failed to add key: "+result.Output)
		}
	}

	return c.JSON(fiber.Map{
		"success":  true,
		"username": username,
		"message":  "SSH key added successfully",
	})
}

/**
 * RemoveSSHKey removes an SSH key from authorized_keys.
 *
 * @param c Fiber context
 * @return error
 */
func RemoveSSHKey(c *fiber.Ctx) error {
	fingerprint := c.Params("fingerprint")
	username := c.Query("username", "root")

	if fingerprint == "" {
		return errorResponse(c, 400, "Fingerprint is required")
	}

	homeDir := "/root"
	if username != "root" {
		homeDir = "/home/" + username
	}

	authKeysPath := homeDir + "/.ssh/authorized_keys"

	// Remove line containing the fingerprint/name
	cmd := fmt.Sprintf("sudo sed -i '/%s/d' %s", fingerprint, authKeysPath)
	result := executeWithTimeout(cmd, 10*time.Second)

	if !result.Success {
		return errorResponse(c, 500, "Failed to remove key: "+result.Output)
	}

	return c.JSON(fiber.Map{
		"success":  true,
		"username": username,
		"message":  "SSH key removed successfully",
	})
}

// =============================================================================
// WEBSOCKET HANDLER
// =============================================================================

// WebSocket clients for broadcasting
var wsClients = make(map[*websocket.Conn]bool)
var wsLock sync.Mutex

/**
 * WebSocketHandler handles WebSocket connections for real-time updates.
 *
 * @param c WebSocket connection
 */
func WebSocketHandler(c *websocket.Conn) {
	// Register client
	wsLock.Lock()
	wsClients[c] = true
	wsLock.Unlock()

	defer func() {
		wsLock.Lock()
		delete(wsClients, c)
		wsLock.Unlock()
		c.Close()
	}()

	// Send initial status
	sendStatus(c)

	// Handle incoming messages
	for {
		_, msg, err := c.ReadMessage()
		if err != nil {
			break
		}

		// Handle ping/pong
		if string(msg) == "ping" {
			c.WriteMessage(websocket.TextMessage, []byte("pong"))
			continue
		}

		// Handle status request
		if string(msg) == "status" {
			sendStatus(c)
		}
	}
}

/**
 * sendStatus sends current system status to a WebSocket client.
 *
 * @param c WebSocket connection
 */
func sendStatus(c *websocket.Conn) {
	cpuPercent, _ := cpu.Percent(0, false)
	memInfo, _ := mem.VirtualMemory()
	loadAvg, _ := load.Avg()

	status := fiber.Map{
		"type":      "status",
		"timestamp": time.Now().Unix(),
		"cpu":       firstFloat(cpuPercent),
		"memory":    memInfo.UsedPercent,
		"load":      loadAvg.Load1,
	}

	c.WriteJSON(status)
}

/**
 * BroadcastMetrics sends metrics to all connected WebSocket clients.
 *
 * @param metrics The metrics to broadcast
 */
func BroadcastMetrics(metrics fiber.Map) {
	wsLock.Lock()
	defer wsLock.Unlock()

	for client := range wsClients {
		if err := client.WriteJSON(metrics); err != nil {
			client.Close()
			delete(wsClients, client)
		}
	}
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * errorResponse sends a standardized error response.
 *
 * @param c Fiber context
 * @param status HTTP status code
 * @param message Error message
 * @return error
 */
func errorResponse(c *fiber.Ctx, status int, message string) error {
	return c.Status(status).JSON(fiber.Map{
		"success": false,
		"error":   message,
	})
}

/**
 * isAllowedPath checks if a path is in the whitelist.
 *
 * @param path The path to check
 * @return bool
 */
func isAllowedPath(path string) bool {
	for _, allowed := range AllowedPaths {
		if strings.HasPrefix(path, allowed) {
			return true
		}
	}
	return false
}

/**
 * isAllowedService checks if a service is in the whitelist.
 *
 * @param name The service name
 * @return bool
 */
func isAllowedService(name string) bool {
	for _, allowed := range AllowedServices {
		if name == allowed {
			return true
		}
	}
	return false
}

/**
 * firstOrEmpty returns the first CPU info or empty struct.
 *
 * @param cpuInfo CPU info slice
 * @return cpu.InfoStat
 */
func firstOrEmpty(cpuInfo []cpu.InfoStat) cpu.InfoStat {
	if len(cpuInfo) > 0 {
		return cpuInfo[0]
	}
	return cpu.InfoStat{}
}

/**
 * firstFloat returns the first float or 0.
 *
 * @param floats Float slice
 * @return float64
 */
func firstFloat(floats []float64) float64 {
	if len(floats) > 0 {
		return floats[0]
	}
	return 0
}

// =============================================================================
// LOG STREAMING (for future use)
// =============================================================================

/**
 * StreamLogs streams a log file to the client.
 *
 * @param path Log file path
 * @param lines Number of lines to tail
 * @param follow Whether to follow new lines
 * @param output Channel to send lines
 */
func StreamLogs(path string, lines int, follow bool, output chan<- string) {
	defer close(output)

	if !isAllowedPath(path) {
		output <- "Error: Access denied"
		return
	}

	args := []string{"-n", fmt.Sprintf("%d", lines)}
	if follow {
		args = append(args, "-f")
	}
	args = append(args, path)

	cmd := exec.Command("tail", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		output <- "Error: " + err.Error()
		return
	}

	if err := cmd.Start(); err != nil {
		output <- "Error: " + err.Error()
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		output <- scanner.Text()
	}

	cmd.Wait()
}
