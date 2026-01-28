/**
 * Watchdog Package
 *
 * Monitors critical services and restarts them if they become unavailable.
 * This is a safety mechanism to prevent lockout when managing SSH remotely.
 *
 * Features:
 * - Periodic SSH service health checks
 * - Automatic SSH restart if service is down
 * - Configurable check intervals and thresholds
 * - Logging of all watchdog actions
 *
 * @package watchdog
 */
package watchdog

import (
	"context"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Default configuration values
const (
	// DefaultCheckInterval is how often to check service status
	DefaultCheckInterval = 30 * time.Second

	// DefaultFailureThreshold is how many consecutive failures before restart
	DefaultFailureThreshold = 2

	// DefaultRestartCooldown is minimum time between restart attempts
	DefaultRestartCooldown = 60 * time.Second

	// DefaultMaxRestarts is max restart attempts before giving up
	DefaultMaxRestarts = 5

	// DefaultMaxRestartsWindow is the time window for counting restarts
	DefaultMaxRestartsWindow = 10 * time.Minute
)

// Config holds the watchdog configuration
type Config struct {
	// Enabled determines if the watchdog is active
	Enabled bool

	// CheckInterval is how often to check service status
	CheckInterval time.Duration

	// FailureThreshold is consecutive failures before restart
	FailureThreshold int

	// RestartCooldown is minimum time between restart attempts
	RestartCooldown time.Duration

	// MaxRestarts is max restart attempts within the time window
	MaxRestarts int

	// MaxRestartsWindow is the time window for counting restarts
	MaxRestartsWindow time.Duration

	// Services is the list of services to monitor
	Services []string
}

// DefaultConfig returns the default watchdog configuration
func DefaultConfig() Config {
	return Config{
		Enabled:           true,
		CheckInterval:     DefaultCheckInterval,
		FailureThreshold:  DefaultFailureThreshold,
		RestartCooldown:   DefaultRestartCooldown,
		MaxRestarts:       DefaultMaxRestarts,
		MaxRestartsWindow: DefaultMaxRestartsWindow,
		Services:          []string{"sshd", "ssh"}, // Both service names for compatibility
	}
}

// ServiceState tracks the state of a monitored service
type ServiceState struct {
	Name             string
	ConsecutiveFails int
	LastCheck        time.Time
	LastRestart      time.Time
	RestartAttempts  []time.Time // Track restart times for rate limiting
	IsHealthy        bool
}

// Watchdog monitors and restarts critical services
type Watchdog struct {
	config     Config
	services   map[string]*ServiceState
	mu         sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	running    bool
}

// New creates a new Watchdog instance
func New(cfg Config) *Watchdog {
	ctx, cancel := context.WithCancel(context.Background())

	w := &Watchdog{
		config:   cfg,
		services: make(map[string]*ServiceState),
		ctx:      ctx,
		cancel:   cancel,
	}

	// Initialize service states
	for _, svc := range cfg.Services {
		w.services[svc] = &ServiceState{
			Name:            svc,
			RestartAttempts: make([]time.Time, 0),
			IsHealthy:       true, // Assume healthy at start
		}
	}

	return w
}

/**
 * Start begins the watchdog monitoring loop.
 * This runs in the background and monitors all configured services.
 */
func (w *Watchdog) Start() {
	if !w.config.Enabled {
		log.Println("[Watchdog] Disabled by configuration")
		return
	}

	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return
	}
	w.running = true
	w.mu.Unlock()

	w.wg.Add(1)
	go w.monitorLoop()

	log.Printf("[Watchdog] Started monitoring services: %v (interval: %v)",
		w.config.Services, w.config.CheckInterval)
}

/**
 * Stop gracefully stops the watchdog.
 */
func (w *Watchdog) Stop() {
	w.mu.Lock()
	if !w.running {
		w.mu.Unlock()
		return
	}
	w.running = false
	w.mu.Unlock()

	w.cancel()
	w.wg.Wait()
	log.Println("[Watchdog] Stopped")
}

/**
 * monitorLoop is the main monitoring loop that runs in the background.
 */
func (w *Watchdog) monitorLoop() {
	defer w.wg.Done()

	ticker := time.NewTicker(w.config.CheckInterval)
	defer ticker.Stop()

	// Initial check
	w.checkAllServices()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			w.checkAllServices()
		}
	}
}

/**
 * checkAllServices checks the health of all monitored services.
 */
func (w *Watchdog) checkAllServices() {
	// Try to find which SSH service name is used on this system
	sshServiceName := w.detectSSHServiceName()
	if sshServiceName == "" {
		log.Println("[Watchdog] Could not detect SSH service name")
		return
	}

	w.checkService(sshServiceName)
}

/**
 * detectSSHServiceName determines whether 'sshd' or 'ssh' is the correct service name.
 *
 * @return string The detected service name, or empty if not found
 */
func (w *Watchdog) detectSSHServiceName() string {
	// Try sshd first (most common on RHEL/CentOS)
	if w.serviceExists("sshd") {
		return "sshd"
	}
	// Try ssh (Debian/Ubuntu)
	if w.serviceExists("ssh") {
		return "ssh"
	}
	return ""
}

/**
 * serviceExists checks if a service exists on the system.
 *
 * @param name The service name to check
 * @return bool True if the service exists
 */
func (w *Watchdog) serviceExists(name string) bool {
	cmd := exec.Command("systemctl", "list-unit-files", name+".service")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), name+".service")
}

/**
 * checkService checks a single service and restarts if needed.
 *
 * @param name The service name to check
 */
func (w *Watchdog) checkService(name string) {
	w.mu.Lock()
	state, exists := w.services[name]
	if !exists {
		// Create state for detected service
		state = &ServiceState{
			Name:            name,
			RestartAttempts: make([]time.Time, 0),
			IsHealthy:       true,
		}
		w.services[name] = state
	}
	w.mu.Unlock()

	isRunning := w.isServiceRunning(name)
	now := time.Now()

	w.mu.Lock()
	defer w.mu.Unlock()

	state.LastCheck = now

	if isRunning {
		// Service is healthy
		if state.ConsecutiveFails > 0 {
			log.Printf("[Watchdog] Service '%s' recovered", name)
		}
		state.ConsecutiveFails = 0
		state.IsHealthy = true
		return
	}

	// Service is not running
	state.ConsecutiveFails++
	state.IsHealthy = false
	log.Printf("[Watchdog] Service '%s' is down (failure %d/%d)",
		name, state.ConsecutiveFails, w.config.FailureThreshold)

	// Check if we should attempt restart
	if state.ConsecutiveFails >= w.config.FailureThreshold {
		w.attemptRestart(state)
	}
}

/**
 * isServiceRunning checks if a systemd service is active.
 *
 * @param name The service name to check
 * @return bool True if the service is running
 */
func (w *Watchdog) isServiceRunning(name string) bool {
	cmd := exec.Command("systemctl", "is-active", "--quiet", name)
	err := cmd.Run()
	return err == nil
}

/**
 * attemptRestart attempts to restart a service with rate limiting.
 *
 * @param state The service state to restart
 */
func (w *Watchdog) attemptRestart(state *ServiceState) {
	now := time.Now()

	// Check cooldown period
	if !state.LastRestart.IsZero() && now.Sub(state.LastRestart) < w.config.RestartCooldown {
		log.Printf("[Watchdog] Service '%s' restart skipped - cooldown period active", state.Name)
		return
	}

	// Clean up old restart attempts outside the window
	validAttempts := make([]time.Time, 0)
	for _, t := range state.RestartAttempts {
		if now.Sub(t) < w.config.MaxRestartsWindow {
			validAttempts = append(validAttempts, t)
		}
	}
	state.RestartAttempts = validAttempts

	// Check if we've exceeded max restarts in the window
	if len(state.RestartAttempts) >= w.config.MaxRestarts {
		log.Printf("[Watchdog] Service '%s' restart skipped - max restarts (%d) reached in window",
			state.Name, w.config.MaxRestarts)
		return
	}

	// Attempt restart
	log.Printf("[Watchdog] Attempting to restart service '%s'...", state.Name)

	cmd := exec.Command("systemctl", "start", state.Name)
	output, err := cmd.CombinedOutput()

	state.LastRestart = now
	state.RestartAttempts = append(state.RestartAttempts, now)

	if err != nil {
		log.Printf("[Watchdog] Failed to restart service '%s': %v - %s",
			state.Name, err, strings.TrimSpace(string(output)))
		return
	}

	// Verify the restart worked
	time.Sleep(2 * time.Second)
	if w.isServiceRunning(state.Name) {
		log.Printf("[Watchdog] Successfully restarted service '%s'", state.Name)
		state.ConsecutiveFails = 0
		state.IsHealthy = true
	} else {
		log.Printf("[Watchdog] Service '%s' restart command succeeded but service is still not running",
			state.Name)
	}
}

/**
 * GetStatus returns the current status of all monitored services.
 *
 * @return map[string]ServiceStatus Status of all services
 */
func (w *Watchdog) GetStatus() map[string]ServiceStatus {
	w.mu.RLock()
	defer w.mu.RUnlock()

	status := make(map[string]ServiceStatus)
	for name, state := range w.services {
		status[name] = ServiceStatus{
			Name:             state.Name,
			IsHealthy:        state.IsHealthy,
			ConsecutiveFails: state.ConsecutiveFails,
			LastCheck:        state.LastCheck,
			LastRestart:      state.LastRestart,
			RestartCount:     len(state.RestartAttempts),
		}
	}
	return status
}

// ServiceStatus is a public view of service state
type ServiceStatus struct {
	Name             string    `json:"name"`
	IsHealthy        bool      `json:"is_healthy"`
	ConsecutiveFails int       `json:"consecutive_fails"`
	LastCheck        time.Time `json:"last_check"`
	LastRestart      time.Time `json:"last_restart"`
	RestartCount     int       `json:"restart_count_in_window"`
}
