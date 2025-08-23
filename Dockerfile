# ---- Build stage ----
FROM python:3.13-slim AS builder
WORKDIR /app
ENV POETRY_VERSION=2.1.4
RUN pip install --no-cache-dir poetry==$POETRY_VERSION
COPY pyproject.toml poetry.lock* /app/
RUN poetry config virtualenvs.create false \
    && poetry install --only main --no-interaction --no-ansi
# ---- Runtime stage ----
FROM python:3.11-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1
COPY --from=builder /usr/local /usr/local
COPY app /app/app
COPY alembic.ini /app/alembic.ini
COPY .env.example /app/.env.example

# Default command: run migrations then start api
CMD alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port ${SERVICE_PORT:-8000}
