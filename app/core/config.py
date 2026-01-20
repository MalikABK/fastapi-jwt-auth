from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # App
    app_name: str = Field(default="fastapi-jwt-auth", alias="APP_NAME")
    env: str = Field(default="development", alias="ENV")

    # Security
    jwt_secret_key: str = Field(min_length=32, alias="JWT_SECRET_KEY")  # Require strong secret key
    jwt_algorithm: str = Field(default="HS256", alias="JWT_ALGORITHM")
    access_token_expire_minutes: int = Field(default=30, alias="ACCESS_TOKEN_EXPIRE_MINUTES")
    refresh_token_expire_days: int = Field(default=7, alias="REFRESH_TOKEN_EXPIRE_DAYS")

    # Security Configuration
    max_login_attempts: int = Field(default=5, alias="MAX_LOGIN_ATTEMPTS")  # Max failed login attempts before lockout
    account_lockout_duration_minutes: int = Field(default=30, alias="ACCOUNT_LOCKOUT_DURATION_MINUTES")  # Duration for account lockout
    password_reset_token_expire_minutes: int = Field(default=60, alias="PASSWORD_RESET_TOKEN_EXPIRE_MINUTES")  # Expire time for password reset tokens

    # Database
    database_url: str = Field(default="", alias="DATABASE_URL")
    test_database_url: str = Field(default="", alias="TEST_DATABASE_URL")

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="forbid",
        case_sensitive=True,
    )


settings = Settings()


