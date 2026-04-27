from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    """Application configuration driven by environment variables and .env file."""

    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # App
    APP_NAME: str = "Damn Vulnerable Startup"
    APP_VERSION: str = "1.0.1"
    DEBUG: bool = True

    # Session signing key
    SECRET_KEY: str = "change-me-in-production"

    # Database
    DATABASE_URL: str = f"sqlite:///{BASE_DIR / 'data' / 'dvs.db'}"

    # CTF
    CTF_MODE: bool = False
    CTF_KEY: str = "default-ctf-key-change-me"

    # LLM provider: mock | openai | anthropic | ollama
    LLM_PROVIDER: str = "mock"
    OPENAI_API_KEY: str = ""
    ANTHROPIC_API_KEY: str = ""
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3.2:3b"

    # Debug
    SQL_ECHO: bool = False

    # Safety
    UNSAFE_CHALLENGES: bool = False

    # Default difficulty tier
    DEFAULT_DIFFICULTY: str = "intern"


settings = Settings()
