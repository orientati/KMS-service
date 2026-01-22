# ---- Build stage ----
FROM python:3.13-slim AS builder
WORKDIR /app
ENV POETRY_VERSION=2.1.4
RUN apt-get update && apt-get install -y --no-install-recommends gcc libpq-dev python3-dev
RUN pip install --no-cache-dir poetry==$POETRY_VERSION
COPY pyproject.toml poetry.lock* /app/
RUN poetry config virtualenvs.create false \
    && poetry install --only main --no-interaction --no-ansi --no-root

# ---- Runtime stage ----
FROM python:3.13-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1

# Install curl for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin -c "Docker image user" appuser

# Copy installed packages from builder
COPY --from=builder /usr/local /usr/local

# Copy application code
COPY app /app/app
COPY alembic.ini /app/alembic.ini

# Change ownership of the application directory to the non-root user
# We need to ensure /app is writable for pycache or temp files if strictly needed,
# though we aim for read-only. For now, owning the files is standard.
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Default command: run migrations then start api
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port ${SERVICE_PORT:-8000}"]
