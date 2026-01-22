from pydantic_settings import SettingsConfigDict, BaseSettings


class Settings(BaseSettings):
    SERVICE_NAME: str = "KMS service"
    SERVICE_VERSION: str = "0.1.0"
    SERVICE_PORT: int = 8000
    JWT_ALGORITHM: str = "RS256"
    ENVIRONMENT: str = "development"
    SENTRY_DSN: str = ""
    SENTRY_RELEASE: str = "0.1.0"
    API_PREFIX: str = "/api/v1"
    DATABASE_URL: str = "postgresql+asyncpg://user:pass@localhost/kms"
    RABBITMQ_HOST: str = "localhost"
    RABBITMQ_PORT: int = 5672
    RABBITMQ_USER: str = "guest"
    RABBITMQ_PASS: str = "guest"
    RABBITMQ_CONNECTION_RETRIES: int = 5
    RABBITMQ_CONNECTION_RETRY_DELAY: int = 5

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_PASSWORD: str | None = None

    # Secret Manager / Vault
    SECRET_MANAGER_TYPE: str = "local"  # local, vault, aws
    VAULT_ADDR: str = "http://localhost:8200"
    VAULT_TOKEN: str | None = None
    VAULT_MOUNT_POINT: str = "secret"
    KMS_MASTER_KEY: str | None = "change-this-to-a-secure-random-string-for-local-dev"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="KMS_"  # Prefisso di tutte le variabili (es. TEMPLATE_DATABASE_URL)
    )

settings = Settings()
