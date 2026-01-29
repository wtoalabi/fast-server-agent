#!/bin/bash
#===============================================================================
# Server Agent Installation Script
#
# This script installs the Fast Server Agent on a server.
# It downloads the agent binary, configures it, and sets up systemd service.
#
# Usage:
#   curl -sSL https://your-domain.com/install-agent.sh | sudo bash
#
# Or with options:
#   curl -sSL https://your-domain.com/install-agent.sh | sudo bash -s -- \
#       --token YOUR_TOKEN \
#       --port 3456 \
#       --control-panel https://your-control-panel.com
#
# Requirements:
#   - Root access (or sudo)
#   - systemd-based Linux distribution
#   - curl or wget
#   - openssl (for token generation if not provided)
#
# @version 1.0.5
# @author Fast Server Management
#===============================================================================

set -euo pipefail

#===============================================================================
# CONFIGURATION
#===============================================================================

# Version is read from VERSION file in repo, or defaults to 1.0.2
# Can be overridden via environment variable or --version flag
DEFAULT_VERSION="1.0.5"
AGENT_VERSION="${AGENT_VERSION:-$DEFAULT_VERSION}"
AGENT_PORT="${AGENT_PORT:-3456}"
AGENT_HOST="${AGENT_HOST:-127.0.0.1}"
AGENT_ALLOWED_IPS="${AGENT_ALLOWED_IPS:-}"
AGENT_USER="${AGENT_USER:-root}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/server-agent}"
LOG_DIR="${LOG_DIR:-/var/log/server-agent}"
CONTROL_PANEL_URL="${CONTROL_PANEL_URL:-}"
DOWNLOAD_BASE="${DOWNLOAD_BASE:-https://github.com/wtoalabi/fast-server-agent/releases/download}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

#===============================================================================
# HELPER FUNCTIONS
#===============================================================================

# Print colored output
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (or with sudo)"
        exit 1
    fi
}

# Detect OS and architecture
detect_system() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$ARCH" in
        x86_64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        armv7l)
            ARCH="arm"
            ;;
        *)
            log_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac

    if [[ "$OS" != "linux" ]]; then
        log_error "Unsupported operating system: $OS (only Linux is supported)"
        exit 1
    fi

    log_info "Detected: ${OS}/${ARCH}"
}

# Check for required commands
check_dependencies() {
    local deps=("systemctl" "curl")
    local missing=()

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required dependencies: ${missing[*]}"
        exit 1
    fi
}

# Generate secure random token
generate_token() {
    if command -v openssl &> /dev/null; then
        openssl rand -hex 32
    elif [[ -f /dev/urandom ]]; then
        head -c 32 /dev/urandom | xxd -p | tr -d '\n'
    else
        # Fallback: use date and random
        echo "$(date +%s%N)$(shuf -i 1000000-9999999 -n 1)" | sha256sum | cut -c1-64
    fi
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --token)
                AGENT_TOKEN="$2"
                shift 2
                ;;
            --port)
                AGENT_PORT="$2"
                shift 2
                ;;
            --host)
                AGENT_HOST="$2"
                shift 2
                ;;
            --bind)
                # Alias for --host for compatibility
                AGENT_HOST="$2"
                shift 2
                ;;
            --allowed-ip)
                # Comma-separated list of allowed IPs
                if [[ -z "${AGENT_ALLOWED_IPS}" ]]; then
                    AGENT_ALLOWED_IPS="$2"
                else
                    AGENT_ALLOWED_IPS="${AGENT_ALLOWED_IPS},$2"
                fi
                shift 2
                ;;
            --control-panel)
                CONTROL_PANEL_URL="$2"
                shift 2
                ;;
            --version)
                AGENT_VERSION="$2"
                shift 2
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# Show help message
show_help() {
    cat << EOF
Fast Server Agent Installer v${AGENT_VERSION}

Usage: $0 [OPTIONS]

Options:
    --token TOKEN       API token for authentication (auto-generated if not provided)
    --port PORT         Port to listen on (default: 3456)
    --host HOST         Host address to bind to (default: 127.0.0.1)
    --bind HOST         Alias for --host
    --allowed-ip IP     IP address allowed to connect (can be used multiple times)
    --control-panel URL Control panel URL for registration
    --version VERSION   Agent version to install (default: ${AGENT_VERSION})
    --help, -h          Show this help message

Examples:
    # Install with auto-generated token
    sudo ./install-agent.sh

    # Install with specific token
    sudo ./install-agent.sh --token my_secure_token_here

    # Install and register with control panel
    sudo ./install-agent.sh --control-panel https://panel.example.com
EOF
}

#===============================================================================
# INSTALLATION FUNCTIONS
#===============================================================================

# Create directories
create_directories() {
    log_info "Creating directories..."

    mkdir -p "${INSTALL_DIR}"
    mkdir -p "${CONFIG_DIR}"
    mkdir -p "${LOG_DIR}"

    chmod 755 "${CONFIG_DIR}"
    chmod 755 "${LOG_DIR}"
}

# Download agent binary
download_agent() {
    log_info "Downloading Server Agent v${AGENT_VERSION}..."

    local download_url="${DOWNLOAD_BASE}/v${AGENT_VERSION}/server-agent-${OS}-${ARCH}"
    local binary_path="${INSTALL_DIR}/server-agent"

    # For development, we'll build from source if binary not available
    if ! curl -sSLf -o "${binary_path}" "${download_url}" 2>/dev/null; then
        log_warning "Could not download pre-built binary"
        log_info "Building from source is required. Run 'make build' in the server-agent directory."
        
        # Create placeholder that will be replaced by actual binary
        cat > "${binary_path}" << 'PLACEHOLDER'
#!/bin/bash
echo "Server Agent binary not installed yet."
echo "Please build from source: cd /path/to/server-agent && go build -o /usr/local/bin/server-agent"
exit 1
PLACEHOLDER
    fi

    chmod +x "${binary_path}"
    log_success "Agent binary installed to ${binary_path}"
}

# Generate or set token
setup_token() {
    if [[ -z "${AGENT_TOKEN:-}" ]]; then
        log_info "Generating secure API token..."
        AGENT_TOKEN=$(generate_token)
    fi

    # Validate token length
    if [[ ${#AGENT_TOKEN} -lt 32 ]]; then
        log_error "Token must be at least 32 characters long"
        exit 1
    fi

    log_success "API token configured"
}

# Create configuration file
create_config() {
    log_info "Creating configuration..."

    cat > "${CONFIG_DIR}/agent.env" << EOF
# Server Agent Configuration
# Generated: $(date -Iseconds)

# API token for authentication (KEEP THIS SECRET!)
AGENT_TOKEN=${AGENT_TOKEN}

# Network configuration
AGENT_HOST=${AGENT_HOST}
AGENT_PORT=${AGENT_PORT}

# Logging
AGENT_LOG_FILE=${LOG_DIR}/agent.log
AGENT_DEBUG=false

# SSH Watchdog Configuration
# Automatically monitors and restarts SSH if it goes down
WATCHDOG_ENABLED=true
WATCHDOG_INTERVAL=30

# Control panel URL (optional)
CONTROL_PANEL_URL=${CONTROL_PANEL_URL}

# Allowed IPs (comma-separated, empty = allow all authenticated requests)
# When AGENT_HOST is 0.0.0.0, this SHOULD be set for security
AGENT_ALLOWED_IPS=${AGENT_ALLOWED_IPS}
EOF

    chmod 600 "${CONFIG_DIR}/agent.env"
    log_success "Configuration saved to ${CONFIG_DIR}/agent.env"
}

# Create systemd service
create_systemd_service() {
    log_info "Creating systemd service..."

    cat > /etc/systemd/system/server-agent.service << EOF
[Unit]
Description=Fast Server Management Agent
Documentation=https://github.com/wtoalabi/fast-server-agent
After=network.target network-online.target
Wants=network-online.target
# Start before sshd so watchdog is ready
Before=sshd.service ssh.service
# Rate limiting for restarts (must be in [Unit] for older systemd)
StartLimitInterval=60
StartLimitBurst=5

[Service]
Type=simple
User=${AGENT_USER}
Group=${AGENT_USER}
EnvironmentFile=${CONFIG_DIR}/agent.env
ExecStart=${INSTALL_DIR}/server-agent \\
    --host \${AGENT_HOST} \\
    --port \${AGENT_PORT} \\
    --allowed-ips \${AGENT_ALLOWED_IPS} \\
    --log \${AGENT_LOG_FILE}
ExecReload=/bin/kill -HUP \$MAINPID

# ============================================================================
# AUTO-RESTART CONFIGURATION
# ============================================================================
# Always restart on failure - critical for maintaining server management access
Restart=always
# Wait 3 seconds before restarting (gives system time to clean up)
RestartSec=3

# ============================================================================
# SYSTEMD WATCHDOG (for the agent itself)
# ============================================================================
# Agent must notify systemd every 60 seconds or it will be restarted
WatchdogSec=60

# ============================================================================
# SECURITY HARDENING
# ============================================================================
NoNewPrivileges=no
ProtectSystem=false
ProtectHome=false
PrivateTmp=false

# ============================================================================
# RESOURCE LIMITS
# ============================================================================
LimitNOFILE=65535
LimitNPROC=4096
# Memory limit increased to 512M to allow dpkg/apt operations
# which can temporarily spike memory usage
MemoryMax=512M

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_success "Systemd service created"
}

# Start and enable service
start_service() {
    log_info "Starting Server Agent service..."

    systemctl enable server-agent --quiet
    systemctl start server-agent

    # Wait for service to start
    sleep 2

    if systemctl is-active --quiet server-agent; then
        log_success "Server Agent is running"
    else
        log_error "Failed to start Server Agent"
        log_error "Check logs: journalctl -u server-agent -f"
        exit 1
    fi
}

# Register with control panel
register_with_panel() {
    if [[ -z "${CONTROL_PANEL_URL}" ]]; then
        return
    fi

    log_info "Registering with control panel..."

    # Get server info
    local hostname=$(hostname)
    local ip_address=$(curl -s https://api.ipify.org 2>/dev/null || echo "unknown")
    local os_info=$(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2 || echo "Linux")

    # Send registration request
    local response
    response=$(curl -sSL -X POST "${CONTROL_PANEL_URL}/api/agent/register" \
        -H "Content-Type: application/json" \
        -d "{
            \"hostname\": \"${hostname}\",
            \"ip_address\": \"${ip_address}\",
            \"os\": \"${os_info}\",
            \"agent_token\": \"${AGENT_TOKEN}\",
            \"agent_port\": ${AGENT_PORT},
            \"agent_version\": \"${AGENT_VERSION}\"
        }" 2>&1) || true

    if echo "$response" | grep -q '"success":true'; then
        log_success "Registered with control panel"
    else
        log_warning "Could not register with control panel (server may not be accessible)"
        log_warning "Please add the server manually in the control panel"
    fi
}

# Print summary
print_summary() {
    echo ""
    echo "==========================================="
    echo "   Server Agent Installation Complete"
    echo "==========================================="
    echo ""
    echo "Agent Version: ${AGENT_VERSION}"
    echo "Listening on:  ${AGENT_HOST}:${AGENT_PORT}"
    echo "Config File:   ${CONFIG_DIR}/agent.env"
    echo "Log File:      ${LOG_DIR}/agent.log"
    echo ""
    echo "API Token (save this securely):"
    echo "${AGENT_TOKEN}"
    echo ""
    echo "Commands:"
    echo "  Status:  systemctl status server-agent"
    echo "  Logs:    journalctl -u server-agent -f"
    echo "  Restart: systemctl restart server-agent"
    echo "  Stop:    systemctl stop server-agent"
    echo ""
    echo "Test health endpoint:"
    echo "  curl -H 'X-Agent-Token: ${AGENT_TOKEN}' http://${AGENT_HOST}:${AGENT_PORT}/api/health"
    echo ""
    echo "==========================================="
}

#===============================================================================
# UNINSTALL FUNCTION
#===============================================================================

uninstall() {
    log_info "Uninstalling Server Agent..."

    # Stop and disable service
    if systemctl is-active --quiet server-agent 2>/dev/null; then
        systemctl stop server-agent
    fi
    if systemctl is-enabled --quiet server-agent 2>/dev/null; then
        systemctl disable server-agent --quiet
    fi

    # Remove files
    rm -f /etc/systemd/system/server-agent.service
    rm -f "${INSTALL_DIR}/server-agent"
    rm -rf "${CONFIG_DIR}"
    rm -rf "${LOG_DIR}"

    systemctl daemon-reload

    log_success "Server Agent uninstalled successfully"
}

#===============================================================================
# MAIN
#===============================================================================

main() {
    echo ""
    echo "==========================================="
    echo "   Fast Server Agent Installer"
    echo "   Version: ${AGENT_VERSION}"
    echo "==========================================="
    echo ""

    # Check for uninstall flag
    if [[ "${1:-}" == "--uninstall" ]]; then
        check_root
        uninstall
        exit 0
    fi

    # Parse arguments
    parse_args "$@"

    # Pre-flight checks
    check_root
    detect_system
    check_dependencies

    # Installation steps
    create_directories
    download_agent
    setup_token
    create_config
    create_systemd_service
    start_service
    register_with_panel

    # Print summary
    print_summary
}

# Run main function
main "$@"
