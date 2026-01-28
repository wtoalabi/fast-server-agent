# Release Process for Server Agent

## Creating a New Release

### 1. Update Version Numbers

Update version in relevant files:
- `scripts/install.sh` - Update `AGENT_VERSION` default
- `main.go` - Update version in HealthCheck handler (if applicable)

### 2. Build Binaries

```bash
# Build for all platforms
make build

# Or build individual platforms
GOOS=linux GOARCH=amd64 go build -o dist/server-agent-linux-amd64 main.go
GOOS=linux GOARCH=arm64 go build -o dist/server-agent-linux-arm64 main.go
```

### 3. Create Git Tag

```bash
# Commit all changes first
git add .
git commit -m "Release v1.0.1"

# Create annotated tag
git tag -a v1.0.1 -m "Release version 1.0.1 - Fixed dpkg interrupted state handling"

# Push commits and tags
git push origin main
git push origin v1.0.1
```

### 4. Create GitHub Release

**Option A: Via GitHub Web UI**
1. Go to https://github.com/wtoalabi/fast-server-agent/releases
2. Click "Draft a new release"
3. Select tag: `v1.0.1`
4. Title: `v1.0.1 - Description`
5. Add release notes describing changes
6. Upload binaries:
   - `server-agent-linux-amd64`
   - `server-agent-linux-arm64`
   - `server-agent-darwin-amd64` (if applicable)
   - `server-agent-darwin-arm64` (if applicable)
7. Click "Publish release"

**Option B: Via GitHub CLI**
```bash
gh release create v1.0.1 \
  --title "v1.0.1 - Fixed dpkg interrupted state" \
  --notes "- Added automatic dpkg state fix
- Fixed update application errors
- Improved error handling" \
  dist/server-agent-*
```

### 5. Update Default Version (Optional)

If you want new installations to use the latest version, update `install.sh`:

```bash
# In scripts/install.sh, change:
AGENT_VERSION="${AGENT_VERSION:-1.0.1}"  # was 1.0.0
```

Then commit and push this change.

## Version Numbering (Semantic Versioning)

Follow [Semantic Versioning](https://semver.org/): `MAJOR.MINOR.PATCH`

- **MAJOR** (1.x.x): Breaking changes
- **MINOR** (x.1.x): New features, backward compatible
- **PATCH** (x.x.1): Bug fixes, backward compatible

### Examples:
- `v1.0.0` → `v1.0.1`: Bug fix (dpkg fix)
- `v1.0.1` → `v1.1.0`: New feature (add monitoring endpoint)
- `v1.1.0` → `v2.0.0`: Breaking change (new API format)

## Installing Specific Versions

Users can install specific versions:

```bash
# Install latest (uses default in install.sh)
curl -sSL https://your-domain.com/install-agent.sh | sudo bash

# Install specific version
export AGENT_VERSION=1.0.1
curl -sSL https://your-domain.com/install-agent.sh | sudo bash -s -- --version 1.0.1
```

## Checking Current Version

On the server:
```bash
server-agent --version
# Or via API:
curl http://localhost:3456/health | jq .version
```
