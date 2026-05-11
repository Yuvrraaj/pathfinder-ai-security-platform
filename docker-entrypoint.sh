#!/bin/bash
set -euo pipefail

# PathFinder Docker Entrypoint
# Handles API key checks, template updates, and signal handling

# =============================================================================
# Signal Handling
# =============================================================================
cleanup() {
    echo "Received shutdown signal, cleaning up..."
    exit 0
}
trap cleanup SIGTERM SIGINT

# =============================================================================
# API Key Check
# =============================================================================
if [[ -z "${GROQ_API_KEY:-}" ]]; then
    echo "WARNING: GROQ_API_KEY is not set"
    echo "  AI-assisted features will use fallback heuristics."
    echo "  Get a free key at: https://console.groq.com"
    echo "  Set via: -e GROQ_API_KEY=gsk_..."
    echo ""
fi

# =============================================================================
# Nuclei Template Update (with locking and caching)
# =============================================================================
TEMPLATE_DIR="${HOME}/.local/nuclei-templates"
LOCK_FILE="${HOME}/.config/nuclei/update.lock"
CACHE_FILE="${HOME}/.config/nuclei/last_update"
CACHE_DURATION=86400  # 24 hours in seconds

update_templates() {
    local now
    now=$(date +%s)

    # Check if cache is still valid
    if [[ -f "${CACHE_FILE}" ]]; then
        local last_update
        last_update=$(cat "${CACHE_FILE}" 2>/dev/null || echo 0)
        local age=$((now - last_update))

        if [[ ${age} -lt ${CACHE_DURATION} ]]; then
            echo "Nuclei templates updated $((age / 3600))h ago, skipping update"
            return 0
        fi
    fi

    echo "Updating nuclei templates..."

    # Use flock for concurrent access protection
    (
        flock -n 200 || {
            echo "Another process is updating templates, waiting..."
            flock 200
        }

        # Double-check cache after acquiring lock (another process may have updated)
        if [[ -f "${CACHE_FILE}" ]]; then
            local last_update
            last_update=$(cat "${CACHE_FILE}" 2>/dev/null || echo 0)
            local age=$((now - last_update))

            if [[ ${age} -lt ${CACHE_DURATION} ]]; then
                echo "Templates were updated by another process"
                return 0
            fi
        fi

        # Perform the update
        if nuclei -ut -ud "${TEMPLATE_DIR}" 2>&1; then
            echo "${now}" > "${CACHE_FILE}"
            echo "Templates updated successfully"
        else
            echo "WARNING: Template update failed, using existing templates"
        fi

    ) 200>"${LOCK_FILE}"
}

# Ensure config directory exists
mkdir -p "${HOME}/.config/nuclei"

# Update templates (with caching)
update_templates

# =============================================================================
# Execute PathFinder
# =============================================================================
exec pathfinder "$@"
