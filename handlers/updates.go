/**
 * Updates Package
 *
 * Contains handlers for server update checking and application.
 * Provides detailed information about available updates including:
 * - OS package updates (apt/yum/dnf)
 * - Security updates
 * - Kernel updates
 * - Service updates
 *
 * @package handlers
 */
package handlers

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

// =============================================================================
// UPDATE STRUCTURES
// =============================================================================

// UpdateInfo represents detailed information about a single update
type UpdateInfo struct {
	PackageName    string `json:"package_name"`
	CurrentVersion string `json:"current_version"`
	NewVersion     string `json:"new_version"`
	Source         string `json:"source"`
	Type           string `json:"type"`      // os_package, security, kernel, software
	Severity       string `json:"severity"`  // critical, high, medium, low
	Description    string `json:"description,omitempty"`
	Size           string `json:"size,omitempty"`
	RequiresReboot bool   `json:"requires_reboot"`
}

// UpdateCheckResult represents the result of an update check
type UpdateCheckResult struct {
	Success        bool         `json:"success"`
	Timestamp      int64        `json:"timestamp"`
	PackageManager string       `json:"package_manager"` // apt, yum, dnf
	Updates        []UpdateInfo `json:"updates"`
	TotalCount     int          `json:"total_count"`
	SecurityCount  int          `json:"security_count"`
	KernelUpdates  int          `json:"kernel_updates"`
	LastChecked    int64        `json:"last_checked"`
}

// ApplyUpdateRequest represents a request to apply updates
type ApplyUpdateRequest struct {
	Packages       []string `json:"packages"`        // List of packages to update (empty = all)
	SecurityOnly   bool     `json:"security_only"`   // Only apply security updates
	AutoReboot     bool     `json:"auto_reboot"`     // Reboot after kernel updates
	DryRun         bool     `json:"dry_run"`         // Simulate only, don't apply
	AllowDowngrade bool     `json:"allow_downgrade"` // Allow package downgrades
}

// ApplyUpdateResult represents the result of applying updates
type ApplyUpdateResult struct {
	Success        bool     `json:"success"`
	PackagesUpdated int     `json:"packages_updated"`
	Packages       []string `json:"packages"`
	Output         string   `json:"output"`
	RequiresReboot bool     `json:"requires_reboot"`
	DurationMs     int64    `json:"duration_ms"`
	Errors         []string `json:"errors,omitempty"`
}

// =============================================================================
// PACKAGE MANAGEMENT DETECTION
// =============================================================================

// PackageManager type for supported package managers
type PackageManagerType string

const (
	PMTypeApt  PackageManagerType = "apt"
	PMTypeYum  PackageManagerType = "yum"
	PMTypeDnf  PackageManagerType = "dnf"
	PMTypeNone PackageManagerType = "none"
)

/**
 * detectPackageManager determines the package manager used by the system.
 *
 * @return PackageManagerType
 */
func detectPackageManager() PackageManagerType {
	// Check for dnf (Fedora, CentOS 8+, RHEL 8+)
	result := executeWithTimeout("which dnf", 5*time.Second)
	if result.Success && strings.TrimSpace(result.Output) != "" {
		return PMTypeDnf
	}

	// Check for yum (CentOS 7, RHEL 7, Amazon Linux)
	result = executeWithTimeout("which yum", 5*time.Second)
	if result.Success && strings.TrimSpace(result.Output) != "" {
		return PMTypeYum
	}

	// Check for apt (Debian, Ubuntu)
	result = executeWithTimeout("which apt", 5*time.Second)
	if result.Success && strings.TrimSpace(result.Output) != "" {
		return PMTypeApt
	}

	return PMTypeNone
}

// =============================================================================
// COMPREHENSIVE UPDATE CHECK HANDLER
// =============================================================================

/**
 * CheckUpdatesDetailed returns comprehensive information about available updates.
 * This is an enhanced version of CheckUpdates that provides more detail.
 *
 * @param c Fiber context
 * @return error
 */
func CheckUpdatesDetailed(c *fiber.Ctx) error {
	pm := detectPackageManager()

	switch pm {
	case PMTypeApt:
		return checkUpdatesApt(c)
	case PMTypeYum:
		return checkUpdatesYum(c)
	case PMTypeDnf:
		return checkUpdatesDnf(c)
	default:
		return errorResponse(c, 500, "No supported package manager found")
	}
}

/**
 * checkUpdatesApt checks for updates using apt (Debian/Ubuntu).
 *
 * @param c Fiber context
 * @return error
 */
func checkUpdatesApt(c *fiber.Ctx) error {
	timestamp := time.Now().Unix()
	updates := []UpdateInfo{}
	securityCount := 0
	kernelCount := 0

	// Update package lists
	executeWithTimeout("sudo apt-get update -qq 2>/dev/null", 120*time.Second)

	// Get upgradable packages with details
	result := executeWithTimeout("apt list --upgradable 2>/dev/null", 60*time.Second)

	if result.Success && result.Output != "" {
		lines := strings.Split(result.Output, "\n")

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "Listing") {
				continue
			}

			update := parseAptLine(line)
			if update != nil {
				updates = append(updates, *update)

				if update.Type == "security" || update.Severity == "critical" || update.Severity == "high" {
					securityCount++
				}
				if update.Type == "kernel" {
					kernelCount++
				}
			}
		}
	}

	// Get additional security update info
	secResult := executeWithTimeout("apt list --upgradable 2>/dev/null | grep -i security | wc -l", 10*time.Second)
	if secResult.Success {
		// securityCount already calculated from parsing
	}

	return c.JSON(UpdateCheckResult{
		Success:        true,
		Timestamp:      timestamp,
		PackageManager: "apt",
		Updates:        updates,
		TotalCount:     len(updates),
		SecurityCount:  securityCount,
		KernelUpdates:  kernelCount,
		LastChecked:    timestamp,
	})
}

/**
 * parseAptLine parses an apt list line into UpdateInfo.
 * Format: package/source version arch [upgradable from: current_version]
 *
 * @param line The apt list output line
 * @return *UpdateInfo
 */
func parseAptLine(line string) *UpdateInfo {
	// Example: nginx/focal-security 1.18.0-0ubuntu1.4 amd64 [upgradable from: 1.18.0-0ubuntu1]
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil
	}

	// Parse package/source
	pkgSource := strings.SplitN(parts[0], "/", 2)
	packageName := pkgSource[0]
	source := ""
	if len(pkgSource) > 1 {
		source = pkgSource[1]
	}

	// Parse new version
	newVersion := parts[1]

	// Parse current version from [upgradable from: x.x.x]
	currentVersion := ""
	re := regexp.MustCompile(`upgradable from: ([^\]]+)`)
	matches := re.FindStringSubmatch(line)
	if len(matches) > 1 {
		currentVersion = strings.TrimSpace(matches[1])
	}

	// Determine type and severity
	updateType, severity := classifyUpdate(packageName, source)

	// Check if requires reboot
	requiresReboot := strings.HasPrefix(strings.ToLower(packageName), "linux-image") ||
		strings.HasPrefix(strings.ToLower(packageName), "linux-headers") ||
		strings.Contains(strings.ToLower(packageName), "systemd") ||
		strings.Contains(strings.ToLower(packageName), "glibc") ||
		strings.Contains(strings.ToLower(packageName), "libc6")

	return &UpdateInfo{
		PackageName:    packageName,
		CurrentVersion: currentVersion,
		NewVersion:     newVersion,
		Source:         source,
		Type:           updateType,
		Severity:       severity,
		RequiresReboot: requiresReboot,
	}
}

/**
 * classifyUpdate determines the type and severity of an update.
 *
 * @param packageName Package name
 * @param source Package source/repository
 * @return (type, severity)
 */
func classifyUpdate(packageName, source string) (string, string) {
	pkgLower := strings.ToLower(packageName)
	sourceLower := strings.ToLower(source)

	// Kernel updates
	if strings.HasPrefix(pkgLower, "linux-image") || strings.HasPrefix(pkgLower, "linux-headers") {
		if strings.Contains(sourceLower, "security") {
			return "kernel", "critical"
		}
		return "kernel", "high"
	}

	// Security source
	if strings.Contains(sourceLower, "security") {
		// Critical security packages
		criticalPackages := []string{"openssl", "openssh", "libssl", "sudo", "kernel", "glibc", "libc6"}
		for _, pkg := range criticalPackages {
			if strings.Contains(pkgLower, pkg) {
				return "security", "critical"
			}
		}
		return "security", "high"
	}

	// Important software
	importantSoftware := []string{"nginx", "apache", "mysql", "mariadb", "postgresql", "php", "redis", "docker"}
	for _, sw := range importantSoftware {
		if strings.Contains(pkgLower, sw) {
			return "software", "medium"
		}
	}

	// Security-related packages (even from non-security sources)
	securityPackages := []string{"openssl", "openssh", "gnupg", "fail2ban", "ufw", "iptables", "apparmor"}
	for _, pkg := range securityPackages {
		if strings.Contains(pkgLower, pkg) {
			return "security", "medium"
		}
	}

	// Default
	return "os_package", "low"
}

/**
 * checkUpdatesYum checks for updates using yum (RHEL/CentOS 7).
 *
 * @param c Fiber context
 * @return error
 */
func checkUpdatesYum(c *fiber.Ctx) error {
	timestamp := time.Now().Unix()
	updates := []UpdateInfo{}
	securityCount := 0
	kernelCount := 0

	// Check for updates
	result := executeWithTimeout("yum check-update -q 2>/dev/null", 120*time.Second)

	// yum check-update returns exit code 100 if updates are available
	if result.Output != "" {
		lines := strings.Split(result.Output, "\n")

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.Contains(line, "Obsoleting") {
				continue
			}

			parts := strings.Fields(line)
			if len(parts) >= 2 {
				packageName := parts[0]
				newVersion := parts[1]

				// Remove arch from package name if present
				if idx := strings.LastIndex(packageName, "."); idx > 0 {
					arch := packageName[idx+1:]
					if arch == "x86_64" || arch == "noarch" || arch == "i686" {
						packageName = packageName[:idx]
					}
				}

				updateType, severity := classifyUpdate(packageName, "")
				requiresReboot := strings.Contains(strings.ToLower(packageName), "kernel")

				updates = append(updates, UpdateInfo{
					PackageName:    packageName,
					NewVersion:     newVersion,
					Type:           updateType,
					Severity:       severity,
					RequiresReboot: requiresReboot,
				})

				if updateType == "security" {
					securityCount++
				}
				if updateType == "kernel" {
					kernelCount++
				}
			}
		}
	}

	// Check specifically for security updates
	secResult := executeWithTimeout("yum updateinfo list security 2>/dev/null | wc -l", 30*time.Second)
	if secResult.Success {
		// Parse count if needed
	}

	return c.JSON(UpdateCheckResult{
		Success:        true,
		Timestamp:      timestamp,
		PackageManager: "yum",
		Updates:        updates,
		TotalCount:     len(updates),
		SecurityCount:  securityCount,
		KernelUpdates:  kernelCount,
		LastChecked:    timestamp,
	})
}

/**
 * checkUpdatesDnf checks for updates using dnf (Fedora/RHEL 8+).
 *
 * @param c Fiber context
 * @return error
 */
func checkUpdatesDnf(c *fiber.Ctx) error {
	timestamp := time.Now().Unix()
	updates := []UpdateInfo{}
	securityCount := 0
	kernelCount := 0

	// Check for updates
	result := executeWithTimeout("dnf check-update -q 2>/dev/null", 120*time.Second)

	if result.Output != "" {
		lines := strings.Split(result.Output, "\n")

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.Contains(line, "Last metadata") {
				continue
			}

			parts := strings.Fields(line)
			if len(parts) >= 2 {
				packageName := parts[0]
				newVersion := parts[1]

				// Remove arch from package name
				if idx := strings.LastIndex(packageName, "."); idx > 0 {
					arch := packageName[idx+1:]
					if arch == "x86_64" || arch == "noarch" || arch == "i686" || arch == "aarch64" {
						packageName = packageName[:idx]
					}
				}

				updateType, severity := classifyUpdate(packageName, "")
				requiresReboot := strings.Contains(strings.ToLower(packageName), "kernel")

				updates = append(updates, UpdateInfo{
					PackageName:    packageName,
					NewVersion:     newVersion,
					Type:           updateType,
					Severity:       severity,
					RequiresReboot: requiresReboot,
				})

				if updateType == "security" {
					securityCount++
				}
				if updateType == "kernel" {
					kernelCount++
				}
			}
		}
	}

	return c.JSON(UpdateCheckResult{
		Success:        true,
		Timestamp:      timestamp,
		PackageManager: "dnf",
		Updates:        updates,
		TotalCount:     len(updates),
		SecurityCount:  securityCount,
		KernelUpdates:  kernelCount,
		LastChecked:    timestamp,
	})
}

// =============================================================================
// APPLY UPDATES HANDLER
// =============================================================================

/**
 * ApplyUpdates applies specified updates or all available updates.
 *
 * @param c Fiber context
 * @return error
 */
func ApplyUpdates(c *fiber.Ctx) error {
	var req ApplyUpdateRequest
	if err := c.BodyParser(&req); err != nil {
		return errorResponse(c, 400, "Invalid request body")
	}

	pm := detectPackageManager()

	switch pm {
	case PMTypeApt:
		return applyUpdatesApt(c, req)
	case PMTypeYum:
		return applyUpdatesYum(c, req)
	case PMTypeDnf:
		return applyUpdatesDnf(c, req)
	default:
		return errorResponse(c, 500, "No supported package manager found")
	}
}

/**
 * applyUpdatesApt applies updates using apt.
 *
 * @param c Fiber context
 * @param req Apply update request
 * @return error
 */
func applyUpdatesApt(c *fiber.Ctx, req ApplyUpdateRequest) error {
	startTime := time.Now()
	errors := []string{}
	packagesUpdated := []string{}

	// Build command
	var cmd string
	if req.DryRun {
		cmd = "sudo apt-get upgrade --dry-run -y"
	} else {
		cmd = "sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y"
	}

	// If specific packages, use install instead
	if len(req.Packages) > 0 {
		pkgList := strings.Join(req.Packages, " ")
		if req.DryRun {
			cmd = fmt.Sprintf("sudo apt-get install --dry-run -y %s", pkgList)
		} else {
			cmd = fmt.Sprintf("sudo DEBIAN_FRONTEND=noninteractive apt-get install -y %s", pkgList)
		}
		packagesUpdated = req.Packages
	}

	// Security only updates
	if req.SecurityOnly && len(req.Packages) == 0 {
		// Use unattended-upgrades for security only
		if req.DryRun {
			cmd = "sudo unattended-upgrade --dry-run"
		} else {
			cmd = "sudo unattended-upgrade"
		}
	}

	// Execute the update
	result := executeWithTimeout(cmd, 600*time.Second) // 10 minute timeout

	if !result.Success {
		errors = append(errors, result.Output)
	}

	// Parse output for updated packages if not specified
	if len(req.Packages) == 0 && result.Success {
		// Parse output for package names (simplified)
		lines := strings.Split(result.Output, "\n")
		for _, line := range lines {
			if strings.Contains(line, "Unpacking") || strings.Contains(line, "Setting up") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					packagesUpdated = append(packagesUpdated, parts[1])
				}
			}
		}
	}

	// Check if reboot is required
	requiresReboot := false
	rebootResult := executeWithTimeout("test -f /var/run/reboot-required && echo yes || echo no", 5*time.Second)
	if rebootResult.Success && strings.TrimSpace(rebootResult.Output) == "yes" {
		requiresReboot = true
	}

	// Auto reboot if requested and required
	if req.AutoReboot && requiresReboot && !req.DryRun {
		// Schedule reboot in 1 minute
		executeWithTimeout("sudo shutdown -r +1 'System update requires reboot'", 5*time.Second)
	}

	duration := time.Since(startTime).Milliseconds()

	return c.JSON(ApplyUpdateResult{
		Success:         result.Success && len(errors) == 0,
		PackagesUpdated: len(packagesUpdated),
		Packages:        packagesUpdated,
		Output:          result.Output,
		RequiresReboot:  requiresReboot,
		DurationMs:      duration,
		Errors:          errors,
	})
}

/**
 * applyUpdatesYum applies updates using yum.
 *
 * @param c Fiber context
 * @param req Apply update request
 * @return error
 */
func applyUpdatesYum(c *fiber.Ctx, req ApplyUpdateRequest) error {
	startTime := time.Now()
	errors := []string{}
	packagesUpdated := []string{}

	// Build command
	var cmd string
	if len(req.Packages) > 0 {
		pkgList := strings.Join(req.Packages, " ")
		if req.DryRun {
			cmd = fmt.Sprintf("sudo yum update --assumeno %s", pkgList)
		} else {
			cmd = fmt.Sprintf("sudo yum update -y %s", pkgList)
		}
		packagesUpdated = req.Packages
	} else if req.SecurityOnly {
		if req.DryRun {
			cmd = "sudo yum update --security --assumeno"
		} else {
			cmd = "sudo yum update --security -y"
		}
	} else {
		if req.DryRun {
			cmd = "sudo yum update --assumeno"
		} else {
			cmd = "sudo yum update -y"
		}
	}

	// Execute the update
	result := executeWithTimeout(cmd, 600*time.Second)

	if !result.Success && !req.DryRun {
		errors = append(errors, result.Output)
	}

	// Check if reboot is required (kernel update)
	requiresReboot := false
	kernelCheck := executeWithTimeout("needs-restarting -r 2>/dev/null || echo 'check'", 10*time.Second)
	if !kernelCheck.Success || strings.Contains(kernelCheck.Output, "Reboot") {
		requiresReboot = true
	}

	duration := time.Since(startTime).Milliseconds()

	return c.JSON(ApplyUpdateResult{
		Success:         result.Success && len(errors) == 0,
		PackagesUpdated: len(packagesUpdated),
		Packages:        packagesUpdated,
		Output:          result.Output,
		RequiresReboot:  requiresReboot,
		DurationMs:      duration,
		Errors:          errors,
	})
}

/**
 * applyUpdatesDnf applies updates using dnf.
 *
 * @param c Fiber context
 * @param req Apply update request
 * @return error
 */
func applyUpdatesDnf(c *fiber.Ctx, req ApplyUpdateRequest) error {
	startTime := time.Now()
	errors := []string{}
	packagesUpdated := []string{}

	// Build command
	var cmd string
	if len(req.Packages) > 0 {
		pkgList := strings.Join(req.Packages, " ")
		if req.DryRun {
			cmd = fmt.Sprintf("sudo dnf upgrade --assumeno %s", pkgList)
		} else {
			cmd = fmt.Sprintf("sudo dnf upgrade -y %s", pkgList)
		}
		packagesUpdated = req.Packages
	} else if req.SecurityOnly {
		if req.DryRun {
			cmd = "sudo dnf upgrade --security --assumeno"
		} else {
			cmd = "sudo dnf upgrade --security -y"
		}
	} else {
		if req.DryRun {
			cmd = "sudo dnf upgrade --assumeno"
		} else {
			cmd = "sudo dnf upgrade -y"
		}
	}

	// Execute the update
	result := executeWithTimeout(cmd, 600*time.Second)

	if !result.Success && !req.DryRun {
		errors = append(errors, result.Output)
	}

	// Check if reboot is required
	requiresReboot := false
	rebootCheck := executeWithTimeout("dnf needs-restarting -r 2>/dev/null", 10*time.Second)
	if !rebootCheck.Success || strings.Contains(rebootCheck.Output, "Reboot") {
		requiresReboot = true
	}

	duration := time.Since(startTime).Milliseconds()

	return c.JSON(ApplyUpdateResult{
		Success:         result.Success && len(errors) == 0,
		PackagesUpdated: len(packagesUpdated),
		Packages:        packagesUpdated,
		Output:          result.Output,
		RequiresReboot:  requiresReboot,
		DurationMs:      duration,
		Errors:          errors,
	})
}

// =============================================================================
// SYSTEM REBOOT HANDLER
// =============================================================================

// RebootRequest represents a reboot request
type RebootRequest struct {
	Delay   int    `json:"delay"`   // Delay in minutes (0 = immediate)
	Message string `json:"message"` // Broadcast message
	Force   bool   `json:"force"`   // Force reboot even if users logged in
}

/**
 * ScheduleReboot schedules or performs a system reboot.
 *
 * @param c Fiber context
 * @return error
 */
func ScheduleReboot(c *fiber.Ctx) error {
	var req RebootRequest
	if err := c.BodyParser(&req); err != nil {
		req = RebootRequest{Delay: 1, Message: "System reboot scheduled"}
	}

	delay := req.Delay
	if delay < 0 {
		delay = 0
	}

	message := req.Message
	if message == "" {
		message = "System reboot scheduled by Fast platform"
	}

	var cmd string
	if delay == 0 {
		cmd = fmt.Sprintf("sudo shutdown -r now '%s'", message)
	} else {
		cmd = fmt.Sprintf("sudo shutdown -r +%d '%s'", delay, message)
	}

	result := executeWithTimeout(cmd, 10*time.Second)

	return c.JSON(fiber.Map{
		"success":       result.Success,
		"message":       fmt.Sprintf("Reboot scheduled in %d minute(s)", delay),
		"scheduled_for": time.Now().Add(time.Duration(delay) * time.Minute).Unix(),
		"output":        result.Output,
	})
}

/**
 * CancelReboot cancels a scheduled reboot.
 *
 * @param c Fiber context
 * @return error
 */
func CancelReboot(c *fiber.Ctx) error {
	result := executeWithTimeout("sudo shutdown -c", 5*time.Second)

	return c.JSON(fiber.Map{
		"success": result.Success,
		"message": "Scheduled reboot cancelled",
		"output":  result.Output,
	})
}

/**
 * RebootRequired checks if a system reboot is required.
 *
 * @param c Fiber context
 * @return error
 */
func RebootRequired(c *fiber.Ctx) error {
	required := false
	reason := ""

	// Check Debian/Ubuntu style
	result := executeWithTimeout("test -f /var/run/reboot-required && cat /var/run/reboot-required || echo 'no'", 5*time.Second)
	if result.Success && !strings.Contains(result.Output, "no") {
		required = true
		reason = strings.TrimSpace(result.Output)
	}

	// Check RHEL/CentOS style
	if !required {
		result = executeWithTimeout("needs-restarting -r 2>/dev/null", 10*time.Second)
		if !result.Success || strings.Contains(result.Output, "Reboot") {
			required = true
			reason = "Kernel or core libraries updated"
		}
	}

	// Check for running kernel vs installed kernel
	if !required {
		runningKernel := executeWithTimeout("uname -r", 5*time.Second)
		installedKernel := executeWithTimeout("ls -1 /lib/modules | sort -V | tail -1", 5*time.Second)
		if runningKernel.Success && installedKernel.Success {
			if strings.TrimSpace(runningKernel.Output) != strings.TrimSpace(installedKernel.Output) {
				required = true
				reason = fmt.Sprintf("Kernel updated: running %s, installed %s",
					strings.TrimSpace(runningKernel.Output),
					strings.TrimSpace(installedKernel.Output))
			}
		}
	}

	return c.JSON(fiber.Map{
		"success":  true,
		"required": required,
		"reason":   reason,
	})
}
