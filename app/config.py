from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator
import os

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=os.getenv("ENV_FILE", ".env.dev"), env_file_encoding="utf-8", extra="ignore")

    ENV: str = Field(default="dev")
    DEBUG: bool = Field(default=True)
    APP_PORT: int = Field(default=8000)
    ALLOWED_ORIGINS: str = Field(default="http://localhost:3000,http://localhost:5173,http://127.0.0.1:8083")
    DATABASE_URL: str

    @property
    def allowed_origins_list(self) -> list[str]:
        return [o.strip() for o in self.ALLOWED_ORIGINS.split(",") if o.strip()]

@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore
