/**
 * Systemd Package
 *
 * Provides integration with systemd for service notifications.
 * This allows the agent to notify systemd that it's alive and healthy,
 * enabling systemd's watchdog feature to restart the agent if it hangs.
 *
 * @package systemd
 */
package systemd

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

/**
 * Notifier handles systemd watchdog notifications.
 * It periodically sends WATCHDOG=1 to the systemd socket to indicate
 * the service is still alive and functioning.
 */
type Notifier struct {
	socket   string
	interval time.Duration
	stopChan chan struct{}
	running  bool
}

/**
 * NewNotifier creates a new systemd notifier.
 * It reads the NOTIFY_SOCKET environment variable to find the systemd socket.
 *
 * @return *Notifier The notifier instance, or nil if not running under systemd
 */
func NewNotifier() *Notifier {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return nil
	}

	// Get watchdog interval from WATCHDOG_USEC
	interval := 30 * time.Second // Default
	if watchdogUSec := os.Getenv("WATCHDOG_USEC"); watchdogUSec != "" {
		// Parse microseconds and use half the value for safety margin
		var usec int64
		if _, err := fmt.Sscanf(watchdogUSec, "%d", &usec); err == nil {
			interval = time.Duration(usec/2) * time.Microsecond
		}
	}

	return &Notifier{
		socket:   socket,
		interval: interval,
		stopChan: make(chan struct{}),
	}
}

/**
 * Start begins sending periodic watchdog notifications to systemd.
 */
func (n *Notifier) Start() {
	if n == nil || n.running {
		return
	}

	n.running = true

	// Send initial READY notification
	n.notify("READY=1")
	log.Printf("[Systemd] Notified READY, watchdog interval: %v", n.interval)

	go func() {
		ticker := time.NewTicker(n.interval)
		defer ticker.Stop()

		for {
			select {
			case <-n.stopChan:
				return
			case <-ticker.C:
				n.notify("WATCHDOG=1")
			}
		}
	}()
}

/**
 * Stop stops the systemd notifier.
 */
func (n *Notifier) Stop() {
	if n == nil || !n.running {
		return
	}

	n.notify("STOPPING=1")
	close(n.stopChan)
	n.running = false
}

/**
 * notify sends a notification message to systemd via the NOTIFY_SOCKET.
 *
 * @param message The notification message (e.g., "READY=1", "WATCHDOG=1")
 */
func (n *Notifier) notify(message string) {
	if n.socket == "" {
		return
	}

	conn, err := net.Dial("unixgram", n.socket)
	if err != nil {
		log.Printf("[Systemd] Failed to connect to notify socket: %v", err)
		return
	}
	defer conn.Close()

	if _, err := conn.Write([]byte(message)); err != nil {
		log.Printf("[Systemd] Failed to send notification: %v", err)
	}
}
