# PathFinder: AI-Assisted External Assessment Platform
# Multi-stage build using pre-built Go binaries for speed

# =============================================================================
# Stage 1: Download pre-built Go scanner binaries
# =============================================================================
FROM alpine:3.19 AS scanner-binaries

# Pin scanner versions for reproducibility
ARG SUBFINDER_VERSION=2.6.6
ARG HTTPX_VERSION=1.6.8
ARG NUCLEI_VERSION=3.3.0

# Install curl and unzip for downloading
RUN apk add --no-cache curl unzip

WORKDIR /binaries

# Download pre-built binaries (much faster than go install)
RUN curl -sSfL "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip" -o subfinder.zip && \
    unzip subfinder.zip -d subfinder && \
    chmod +x subfinder/subfinder

RUN curl -sSfL "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_amd64.zip" -o httpx.zip && \
    unzip httpx.zip -d httpx && \
    chmod +x httpx/httpx

RUN curl -sSfL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -o nuclei.zip && \
    unzip nuclei.zip -d nuclei && \
    chmod +x nuclei/nuclei

# =============================================================================
# Stage 2: Runtime environment
# =============================================================================
FROM python:3.11-slim AS runtime

# Install runtime dependencies and tini
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tini \
        util-linux \
        ca-certificates \
        git \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd --gid 1000 pathfinder && \
    useradd --uid 1000 --gid 1000 --create-home --shell /bin/bash pathfinder

# Copy scanner binaries from build stage
COPY --from=scanner-binaries /binaries/subfinder/subfinder /usr/local/bin/
COPY --from=scanner-binaries /binaries/httpx/httpx /usr/local/bin/
COPY --from=scanner-binaries /binaries/nuclei/nuclei /usr/local/bin/

# Verify binaries are executable
RUN subfinder -version && httpx -version && nuclei -version

# Set working directory and environment
WORKDIR /app
ENV HOME=/home/pathfinder
ENV PATH="/home/pathfinder/.local/bin:${PATH}"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Copy and install Python package
COPY --chown=pathfinder:pathfinder pyproject.toml README.md ./
COPY --chown=pathfinder:pathfinder src/ ./src/

# Install pathfinder
RUN pip install --no-cache-dir -e .

# Create directories for output
RUN mkdir -p /home/pathfinder/.pathfinder /home/pathfinder/.config/nuclei /reports && \
    chown -R pathfinder:pathfinder /home/pathfinder /reports

# Copy entrypoint script
COPY --chown=pathfinder:pathfinder docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Switch to non-root user
USER pathfinder

# Use tini as init system
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"]
CMD ["--help"]
