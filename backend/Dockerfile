# Use Python 3.12 slim image as base
FROM python:3.12-slim

# Install build dependencies for Rust compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv for fast dependency management
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Set working directory
WORKDIR /app

# Copy and install opaque-snake first (for better layer caching)
COPY opaque-snake/ /opaque-snake/
RUN uv pip install --system /opaque-snake/

# Copy pyproject.toml first for better layer caching
COPY reeeductio/pyproject.toml /app/

# Install dependencies using uv (opaque-snake is already installed)
RUN uv pip install --system -r pyproject.toml

# Copy backend application code
COPY reeeductio/backend/ /app/backend/

# Set working directory to backend
WORKDIR /app/backend

# Create directories for persistent data
RUN mkdir -p /data/blobs

# Create volume mount points for configuration and persistent storage
VOLUME ["/data"]
VOLUME ["/config"]

# Expose port 8000 for FastAPI
EXPOSE 8000

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Run the FastAPI application with uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
