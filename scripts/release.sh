#!/bin/bash
#===============================================================================
# Server Agent Release Script
#
# This script automates the release process:
# 1. Builds all platform binaries
# 2. Creates and pushes a git tag
# 3. Commits and pushes changes to GitHub
#
# Usage:
#   ./scripts/release.sh
#
# Requirements:
#   - Git repository with remote 'origin'
#   - VERSION file in project root
#   - Makefile with 'all' target
#
# @author Fast Server Management
#===============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
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

# Check if we're in a git repository
check_git_repo() {
    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        log_error "Not in a git repository"
        exit 1
    fi
}

# Read version from VERSION file
get_version() {
    if [[ ! -f VERSION ]]; then
        log_error "VERSION file not found"
        exit 1
    fi
    
    VERSION=$(cat VERSION | tr -d '\n' | tr -d ' ')
    
    if [[ -z "$VERSION" ]]; then
        log_error "VERSION file is empty"
        exit 1
    fi
    
    echo "$VERSION"
}

# Check for uncommitted changes
check_working_directory() {
    if [[ -n $(git status --porcelain) ]]; then
        log_warning "You have uncommitted changes:"
        git status --short
        echo ""
        read -p "Do you want to commit these changes? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            return 0
        else
            log_error "Please commit or stash your changes before releasing"
            exit 1
        fi
    fi
    return 1
}

# Commit changes
commit_changes() {
    local version=$1
    
    log_info "Staging all changes..."
    git add .
    
    log_info "Committing changes..."
    git commit -m "chore: release v${version}" || {
        log_warning "Nothing to commit (working directory clean)"
    }
}

# Build binaries
build_binaries() {
    log_info "Building binaries for all platforms..."
    
    if ! make all; then
        log_error "Build failed"
        exit 1
    fi
    
    log_success "Binaries built successfully"
}

# Create and push git tag
create_and_push_tag() {
    local version=$1
    local tag="v${version}"
    
    # Check if tag already exists
    if git rev-parse "$tag" >/dev/null 2>&1; then
        log_warning "Tag $tag already exists"
        read -p "Do you want to delete and recreate it? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log_info "Deleting local tag $tag..."
            git tag -d "$tag"
            
            log_info "Deleting remote tag $tag..."
            git push origin ":refs/tags/$tag" 2>/dev/null || true
        else
            log_error "Aborting release"
            exit 1
        fi
    fi
    
    log_info "Creating tag $tag..."
    git tag -a "$tag" -m "Release version ${version}"
    
    log_info "Pushing tag to origin..."
    git push origin "$tag"
    
    log_success "Tag $tag created and pushed"
}

# Push commits to origin
push_commits() {
    local branch=$(git rev-parse --abbrev-ref HEAD)
    
    log_info "Pushing commits to origin/$branch..."
    git push origin "$branch"
    
    log_success "Commits pushed to origin/$branch"
}

# Display release summary
display_summary() {
    local version=$1
    local tag="v${version}"
    
    echo ""
    echo "==========================================="
    echo "   Release Complete!"
    echo "==========================================="
    echo ""
    echo "Version:  ${version}"
    echo "Tag:      ${tag}"
    echo ""
    echo "Next steps:"
    echo "1. Go to GitHub: https://github.com/wtoalabi/fast-server-agent/releases"
    echo "2. Create a new release for tag ${tag}"
    echo "3. Upload the binaries from dist/ folder:"
    echo "   - dist/server-agent-linux-amd64"
    echo "   - dist/server-agent-linux-arm64"
    echo "   - dist/server-agent-linux-arm"
    echo ""
    echo "==========================================="
}

# Main function
main() {
    echo ""
    echo "==========================================="
    echo "   Fast Server Agent - Release Script"
    echo "==========================================="
    echo ""
    
    # Pre-flight checks
    check_git_repo
    
    # Get version
    VERSION=$(get_version)
    log_info "Version: ${VERSION}"
    
    # Check for uncommitted changes and commit if needed
    if check_working_directory; then
        commit_changes "$VERSION"
    fi
    
    # Build binaries
    build_binaries
    
    # Create and push tag
    create_and_push_tag "$VERSION"
    
    # Push commits
    push_commits
    
    # Display summary
    display_summary "$VERSION"
}

# Run main function
main "$@"
