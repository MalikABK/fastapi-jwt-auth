FROM python:3.12-slim as base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install only necessary packages and clean up cache
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

WORKDIR /app

RUN pip install --upgrade pip && pip install uv

COPY pyproject.toml uv.lock ./

RUN uv sync --frozen --no-dev


FROM python:3.12-slim AS runtime

# Create non-root user with minimal permissions
RUN groupadd -r appuser --gid=1001 && useradd -r -g appuser --uid=1001 appuser

WORKDIR /app

# Copy both the Python packages and the uv executable from the base stage
COPY --from=base /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=base /usr/local/bin/uv /usr/local/bin/uv

COPY . .

# Create cache directory for uv and set ownership to non-root user
RUN mkdir -p /home/appuser/.cache/uv && \
    mkdir -p /app/.uv-cache && \
    chown -R appuser:appuser /home/appuser && \
    chown -R appuser:appuser /app
# Set permissions to prevent unauthorized writes
RUN chmod -R 755 /app

USER appuser

# Set UV cache directory to a location within the app directory
ENV UV_CACHE_DIR=/app/.uv-cache

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

CMD ["uv", "run", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
