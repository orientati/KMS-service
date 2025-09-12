from pydantic_settings import SettingsConfigDict, BaseSettings


class Settings(BaseSettings):
    SERVICE_NAME: str = "KMS service"
    SERVICE_VERSION: str = "0.1.0"
    SERVICE_PORT: int = 8000
    ENVIRONMENT: str = "development"
    SENTRY_DSN: str = ""
    SENTRY_RELEASE: str = "0.1.0"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="KMS_"  # Prefisso di tutte le variabili (es. TEMPLATE_DATABASE_URL)
    )

settings = Settings()
