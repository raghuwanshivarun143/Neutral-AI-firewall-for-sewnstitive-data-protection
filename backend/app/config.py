from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # Application
    app_host: str = Field(
        default="127.0.0.1",
        validation_alias="APP_HOST"
    )

    app_port: int = Field(
        default=8000,
        validation_alias="APP_PORT"
    )

    app_version: str = Field(
        default="1.0.0",
        validation_alias="APP_VERSION"
    )

    frontend_url: str = Field(
        default="http://localhost:3000",
        validation_alias="FRONTEND_URL"
    )

    log_level: str = Field(
        default="INFO",
        validation_alias="LOG_LEVEL"
    )

    # Database
    database_url: str = Field(
        default="sqlite:///./cipher01.db",
        validation_alias="DATABASE_URL"
    )

    # OpenAI
    openai_api_key: str = Field(
        default="",
        validation_alias="OPENAI_API_KEY"
    )

    openai_base_url: str = Field(
        default="https://api.openai.com/v1",
        validation_alias="OPENAI_BASE_URL"
    )

    # Anthropic
    anthropic_api_key: str = Field(
        default="",
        validation_alias="ANTHROPIC_API_KEY"
    )

    anthropic_base_url: str = Field(
        default="https://api.anthropic.com",
        validation_alias="ANTHROPIC_BASE_URL"
    )

    # Groq
    groq_api_key: str = Field(
        default="",
        validation_alias="GROQ_API_KEY"
    )

    # Ollama
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        validation_alias="OLLAMA_BASE_URL"
    )

    # Provider defaults
    default_provider: str = Field(
        default="openai",
        validation_alias="DEFAULT_PROVIDER"
    )

    default_model: str = Field(
        default="gpt-4o-mini",
        validation_alias="DEFAULT_MODEL"
    )

    # Security / scanning
    max_decode_depth: int = Field(
        default=3,
        validation_alias="MAX_DECODE_DEPTH"
    )

    max_payload_size_mb: int = Field(
        default=10,
        validation_alias="MAX_PAYLOAD_SIZE_MB"
    )

    enable_canary_tokens: bool = Field(
        default=True,
        validation_alias="ENABLE_CANARY_TOKENS"
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


# Global settings instance
settings = get_settings()