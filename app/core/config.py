from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # App
    app_name: str = Field(default="fastapi-jwt-auth", alias="APP_NAME")
    env: str = Field(default="development", alias="ENV")

    # Security
    jwt_secret_key: str = Field(default="", alias="JWT_SECRET_KEY")
    jwt_algorithm: str = Field(default="HS256", alias="JWT_ALGORITHM")
    access_token_expire_minutes: int = Field(default=30, alias="ACCESS_TOKEN_EXPIRE_MINUTES")

    # Database
    database_url: str = Field(default="", alias="DATABASE_URL")

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="forbid",
        case_sensitive=True,
    )


settings = Settings()
