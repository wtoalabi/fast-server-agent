# Fast Server Agent

A lightweight, high-performance server management daemon written in Go. Provides ultra-fast command execution (10-50ms) compared to SSH (500ms-2s) by running locally on each managed server.

## Features

- **Ultra-Fast**: 10-50ms response time vs 500ms-2s for SSH
- **Lightweight**: ~5MB RAM, minimal CPU usage
- **Secure**: API token authentication, localhost-only by default
- **Complete**: Command execution, file operations, service management, metrics

## Architecture

```
Laravel App (Control Panel)
    ↓ HTTP (via SSH tunnel or private network)
Server Agent (Go daemon on port 3456)
    ↓ Local execution
Server Resources (files, services, etc.)
```

## Installation

### Quick Install (Remote)

```bash
curl -sSL https://your-domain.com/install-agent.sh | sudo bash
```

### Manual Installation

1. Build the agent:
```bash
cd server-agent
make build
```

2. Copy binary to server:
```bash
scp build/server-agent user@server:/usr/local/bin/
```

3. Run install script:
```bash
sudo ./scripts/install.sh --token YOUR_TOKEN
```

## Building

### Requirements

- Go 1.21+
- Make

### Build Commands

```bash
# Build for current platform
make build

# Build for all platforms (linux/amd64, linux/arm64, linux/arm)
make all

# Run tests
make test

# Run locally for development
make run
```

## API Endpoints

### Health & Status

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/info` | System information |
| GET | `/api/metrics` | Current system metrics |

### Command Execution

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/exec` | Execute a command |
| POST | `/api/exec/batch` | Execute multiple commands |

### File Operations

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/file/read` | Read file contents |
| POST | `/api/file/write` | Write file contents |
| POST | `/api/file/exists` | Check if file exists |
| POST | `/api/file/stat` | Get file information |

### Service Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/service/:name/status` | Get service status |
| POST | `/api/service/:name/start` | Start service |
| POST | `/api/service/:name/stop` | Stop service |
| POST | `/api/service/:name/restart` | Restart service |
| POST | `/api/service/:name/enable` | Enable service |
| POST | `/api/service/:name/disable` | Disable service |

### SSH Key Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/ssh/keys` | List SSH keys |
| POST | `/api/ssh/keys` | Add SSH key |
| DELETE | `/api/ssh/keys/:fingerprint` | Remove SSH key |

## Usage Examples

### Execute Command

```bash
curl -X POST http://127.0.0.1:3456/api/exec \
  -H "X-Agent-Token: your-token" \
  -H "Content-Type: application/json" \
  -d '{"command": "whoami"}'
```

Response:
```json
{
  "success": true,
  "output": "root",
  "exit_code": 0,
  "duration_ms": 12
}
```

### Read File

```bash
curl -X POST http://127.0.0.1:3456/api/file/read \
  -H "X-Agent-Token: your-token" \
  -H "Content-Type: application/json" \
  -d '{"path": "/etc/ssh/sshd_config", "sudo": true}'
```

### Service Status

```bash
curl http://127.0.0.1:3456/api/service/nginx/status \
  -H "X-Agent-Token: your-token"
```

Response:
```json
{
  "success": true,
  "service": "nginx",
  "active": true,
  "enabled": true,
  "status": "active"
}
```

## Security

### Authentication

All API endpoints (except `/`) require the `X-Agent-Token` header:

```
X-Agent-Token: your-64-character-hex-token
```

### Network Security

By default, the agent only listens on `127.0.0.1:3456`. Access from the control panel is achieved via:

1. **SSH Tunnel** (recommended): 
   ```bash
   ssh -L 3456:127.0.0.1:3456 user@server
   ```

2. **Private Network**: Configure agent to listen on private IP

3. **VPN**: Access via VPN connection

### Path Whitelisting

File operations are restricted to whitelisted paths:
- `/etc/ssh/`
- `/etc/nginx/`
- `/etc/php/`
- `/var/log/`
- `/home/`
- `/var/www/`
- etc.

### Service Whitelisting

Only whitelisted services can be managed:
- ssh, sshd
- nginx, apache2
- mysql, postgresql
- php-fpm
- redis
- etc.

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AGENT_TOKEN` | API authentication token | Required |
| `AGENT_HOST` | Listen address | `127.0.0.1` |
| `AGENT_PORT` | Listen port | `3456` |
| `AGENT_LOG_FILE` | Log file path | `/var/log/server-agent.log` |
| `AGENT_DEBUG` | Enable debug mode | `false` |

### Command Line Flags

```bash
server-agent \
  --host 127.0.0.1 \
  --port 3456 \
  --token YOUR_TOKEN \
  --log /var/log/server-agent.log \
  --debug
```

## Systemd Service

The install script creates a systemd service:

```bash
# Status
systemctl status server-agent

# Logs
journalctl -u server-agent -f

# Restart
systemctl restart server-agent

# Stop
systemctl stop server-agent
```

## Performance Benchmarks

| Operation | SSH (Pooled) | Agent | Improvement |
|-----------|--------------|-------|-------------|
| Single command | 100-300ms | 10-20ms | 10-15x |
| Read config file | 150-400ms | 15-25ms | 10-15x |
| Service status | 150-400ms | 15-25ms | 10-15x |
| Batch (5 commands) | 500-1000ms | 30-50ms | 15-20x |
| Full page load | 4-12 seconds | 200-500ms | 20-60x |

## Troubleshooting

### Agent Not Responding

1. Check if running: `systemctl status server-agent`
2. Check logs: `journalctl -u server-agent -n 50`
3. Test locally: `curl http://127.0.0.1:3456/`

### Authentication Errors

1. Verify token in `/etc/server-agent/agent.env`
2. Ensure token matches control panel configuration
3. Check for whitespace in token

### Permission Errors

The agent runs as root by default for full system access. For restricted access, configure sudo rules.

## License

MIT License - see LICENSE file.
