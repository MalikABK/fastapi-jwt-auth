from pydantic import Field, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict
import os
import secrets


class Settings(BaseSettings):
    # App
    app_name: str = Field(default="fastapi-jwt-auth", alias="APP_NAME")
    env: str = Field(default="development", alias="ENV")

    # Security
    jwt_secret_key: str = Field(default_factory=lambda: os.getenv('JWT_SECRET_KEY', secrets.token_urlsafe(32)), alias="JWT_SECRET_KEY")  # Require strong secret key
    jwt_algorithm: str = Field(default="HS256", alias="JWT_ALGORITHM")
    access_token_expire_minutes: int = Field(default=30, alias="ACCESS_TOKEN_EXPIRE_MINUTES")
    refresh_token_expire_days: int = Field(default=7, alias="REFRESH_TOKEN_EXPIRE_DAYS")

    # Security Configuration
    max_login_attempts: int = Field(default=5, alias="MAX_LOGIN_ATTEMPTS")  # Max failed login attempts before lockout
    account_lockout_duration_minutes: int = Field(default=30, alias="ACCOUNT_LOCKOUT_DURATION_MINUTES")  # Duration for account lockout
    password_reset_token_expire_minutes: int = Field(default=60, alias="PASSWORD_RESET_TOKEN_EXPIRE_MINUTES")  # Expire time for password reset tokens

    # Database
    database_url: str = Field(alias="DATABASE_URL")  # Make this required
    test_database_url: str = Field(default="", alias="TEST_DATABASE_URL")

    # Redis
    redis_host: str = Field(default="localhost", alias="REDIS_HOST")
    redis_port: int = Field(default=6379, alias="REDIS_PORT")
    redis_password: str = Field(default="", alias="REDIS_PASSWORD")
    redis_db: int = Field(default=0, alias="REDIS_DB")

    # Email settings
    smtp_host: str = Field(default="smtp.gmail.com", alias="SMTP_HOST")
    smtp_port: int = Field(default=587, alias="SMTP_PORT")
    smtp_username: str = Field(default="", alias="SMTP_USERNAME")
    smtp_password: str = Field(default="", alias="SMTP_PASSWORD")
    email_sender: str = Field(default="", alias="EMAIL_SENDER")
    frontend_url: str = Field(default="http://localhost:3000", alias="FRONTEND_URL")  # Your frontend URL

    # Unosend SMTP specific settings
    unosend_track_opens: bool = Field(default=False, alias="UNOSEND_TRACK_OPENS")  # Enable open tracking
    unosend_track_clicks: bool = Field(default=False, alias="UNOSEND_TRACK_CLICKS")  # Enable click tracking
    unosend_tags: str = Field(default="", alias="UNOSEND_TAGS")  # Comma-separated tags for categorization

    # Mailgun settings (alternative to SMTP)
    mailgun_api_key: str = Field(default="", alias="MAILGUN_API_KEY")
    mailgun_domain: str = Field(default="", alias="MAILGUN_DOMAIN")
    mailgun_sender: str = Field(default="", alias="MAILGUN_SENDER")

    # Resend settings (alternative to SMTP and Mailgun)
    resend_api_key: str = Field(default="", alias="RESEND_API_KEY")
    resend_sender: str = Field(default="", alias="RESEND_SENDER")

    # Additional settings
    env: str = Field(default="development", alias="ENVIRONMENT")
    debug: bool = Field(default=False, alias="DEBUG")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    superuser_email: str = Field(default="admin@example.com", alias="SUPERUSER_EMAIL")
    superuser_password: str = Field(default="AdminPass123!", alias="SUPERUSER_PASSWORD")

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="forbid",
        case_sensitive=True,
    )

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # Validate JWT secret key length in production
        if self.env != "development" and len(self.jwt_secret_key) < 32:
            raise ValidationError("JWT_SECRET_KEY must be at least 32 characters long in production")


settings = Settings()


