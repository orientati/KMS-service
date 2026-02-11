# ---- Build stage ----
FROM python:3.11-slim AS builder

WORKDIR /app

ENV POETRY_VERSION=2.1.4

# Install poetry and the export plugin
RUN pip install --no-cache-dir poetry==$POETRY_VERSION \
    && poetry self add poetry-plugin-export

COPY pyproject.toml /app/

# Generate a fresh lock and export requirements to avoid any consistency issues
# We use --without-hashes for faster installation and to avoid mismatches
RUN poetry lock && poetry export -f requirements.txt --output requirements.txt --without-hashes --only main

# Install all dependencies into a target directory to ensure they are captured flatly
RUN pip install --no-cache-dir --target /dependencies -r requirements.txt

# ---- Runtime stage ----

FROM gcr.io/distroless/python3-debian12

WORKDIR /app

ENV PYTHONUNBUFFERED=1
# Distroless Python 3.11 matches this path
ENV PYTHONPATH=/usr/lib/python3.11/site-packages

# Copy dependencies from builder
COPY --from=builder /dependencies /usr/lib/python3.11/site-packages

# Copy app code
COPY . /app

EXPOSE 8000

# Run as nonroot (built-in in the distroless image)
USER nonroot

ENTRYPOINT []

CMD ["python3", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]