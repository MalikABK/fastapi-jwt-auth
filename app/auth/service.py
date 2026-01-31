import logging
from sqlmodel import Session, select
from fastapi import HTTPException, status
from app.models.user import UserCreate, User
from app.models.token_blacklist import TokenBlacklist
from app.auth.security import hash_password, verify_password
from typing import Dict
from app.auth.jwt import create_access_token, create_refresh_token
from datetime import datetime, timedelta, timezone
from app.core.config import settings
import secrets

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)



def create_user(*, session: Session, user_in: UserCreate) -> User:
    logger.info(f"Creating user with email: {user_in.email}")

    # 1. Check if user already exists
    statement = select(User).where(User.email == user_in.email)
    existing_user = session.exec(statement).first()

    if existing_user:
        logger.warning(f"Attempt to create user with existing email: {user_in.email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    # 2. Hash password
    hashed_password = hash_password(user_in.password)

    # 3. Generate email verification token
    verification_token = secrets.token_urlsafe(32)
    verification_expires = datetime.utcnow() + timedelta(hours=24)  # 24-hour expiry

    # 4. Create User object
    user = User(
        email=user_in.email,
        hashed_password=hashed_password,
        full_name=user_in.full_name,
        email_verification_token=verification_token,
        email_verification_expires=verification_expires
    )

    # 5. Persist to database
    try:
        session.add(user)
        session.commit()
        session.refresh(user)
        logger.info(f"Successfully created user with ID: {user.id}")

        # Send verification email (mock implementation)
        send_verification_email(user.email, verification_token)
    except Exception as e:
        session.rollback()
        logger.error(f"Failed to create user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to create user: {str(e)}"
        )

    return user

def authenticate_user(
    *, session: Session, email: str, password: str
) -> Dict[str, str]:
    """
    Authenticate a user and return both access and refresh tokens.
    Raises HTTPException on failure.
    """
    logger.info(f"Authenticating user: {email}")
    statement = select(User).where(User.email == email)
    user = session.exec(statement).first()

    # Check if user exists and account is not locked
    if user:
        logger.debug(f"User found, checking account status for: {email}")

        # Check if account is temporarily locked
        if user.locked_until:
            # Ensure both datetimes have timezone info for comparison
            locked_until_tz = user.locked_until if user.locked_until.tzinfo else user.locked_until.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            if locked_until_tz > now:
                logger.warning(f"Account is locked for user: {email}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Account is temporarily locked due to multiple failed login attempts",
                )

        # Check if email is verified (skip in test environment)
        import os
        if not user.is_verified and os.getenv("ENVIRONMENT") != "test":
            logger.warning(f"Unverified email attempted login: {email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Email not verified. Please verify your email address.",
            )

        # Check password
        if verify_password(password, user.hashed_password):
            logger.info(f"Successful authentication for user: {email}")
            # Reset failed attempts on successful login
            if user.failed_login_attempts > 0:
                user.failed_login_attempts = 0
                user.locked_until = None
        else:
            # Increment failed login attempts
            user.failed_login_attempts += 1
            logger.warning(f"Failed login attempt #{user.failed_login_attempts} for user: {email}")

            # Lock account after max attempts for configured duration
            if user.failed_login_attempts >= settings.max_login_attempts:
                user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=settings.account_lockout_duration_minutes)
                logger.warning(f"Account locked for user: {email} due to multiple failed attempts")

            session.add(user)
            session.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
            )
    else:
        logger.warning(f"Authentication attempt for non-existent user: {email}")
        # Even if user doesn't exist, we still want to increment a counter-like behavior
        # to prevent timing attacks, but for non-existent users we just return error
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    if not user.is_active:
        logger.warning(f"Inactive user attempted login: {email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user",
        )

    # Generate tokens
    access_token = create_access_token(subject=str(user.id))
    refresh_token = create_refresh_token(subject=str(user.id))

    # Optional: store refresh token for revocation support
    user.refresh_token = refresh_token
    session.add(user)
    session.commit()
    logger.info(f"Tokens generated for user: {email}")

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


def blacklist_access_token(*, session: Session, token: str, user_id: int, reason: str = "User logged out") -> None:
    """
    Add an access token to the blacklist to invalidate it before expiration.
    """
    logger.info(f"Blacklisting access token for user ID: {user_id}, reason: {reason}")

    # Decode the token to get its expiration time
    from jose import jwt
    from app.core.config import settings

    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        exp = payload.get("exp")
        expires_at = datetime.fromtimestamp(exp, tz=timezone.utc) if exp else datetime.now(timezone.utc) + timedelta(minutes=30)

        # Create a new TokenBlacklist entry
        blacklisted_token = TokenBlacklist(
            token=token,
            user_id=user_id,
            token_type="access",
            expires_at=expires_at,
            reason=reason
        )

        session.add(blacklisted_token)
        session.commit()
        logger.info(f"Successfully blacklisted token for user ID: {user_id}")
    except Exception as e:
        logger.error(f"Error decoding token for blacklisting: {str(e)}")
        # If we can't decode the token, still try to add it to blacklist
        # Set a reasonable default expiration (30 minutes from now)
        blacklisted_token = TokenBlacklist(
            token=token,
            user_id=user_id,
            token_type="access",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
            reason=reason
        )

        session.add(blacklisted_token)
        session.commit()
        logger.info(f"Token added to blacklist with default expiration for user ID: {user_id}")


def send_verification_email(email: str, verification_token: str):
    """
    Function to send verification email using either Resend, Mailgun, or SMTP
    """
    from app.core.config import settings
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    import requests
    import resend

    # Determine which email service to use
    if settings.resend_api_key and settings.resend_sender:
        # Use Resend
        try:
            resend.api_key = settings.resend_api_key

            verification_link = f"{settings.frontend_url}/verify-email?token={verification_token}"

            params = {
                "from": settings.resend_sender,
                "to": [email],
                "subject": "Verify your email address",
                "html": f"""
        <p>Hello,</p>
        <p>Thank you for signing up! Please click the link below to verify your email address:</p>
        <p><a href="{verification_link}">Verify Email Address</a></p>
        <p>This link will expire in 24 hours.</p>
        <p>If you didn't create an account, please ignore this email.</p>
        """,
                "text": f"""
        Hello,

        Thank you for signing up! Please click the link below to verify your email address:

        {verification_link}

        This link will expire in 24 hours.

        If you didn't create an account, please ignore this email.
        """
            }

            response = resend.Emails.send(params)

            logger.info(f"Verification email sent successfully to {email} via Resend with ID: {response['id']}")
        except Exception as e:
            logger.error(f"Error sending verification email via Resend: {str(e)}")
            # Fallback to logging the token for debugging
            logger.info(f"Verification token for {email}: {verification_token}")

    elif settings.mailgun_api_key and settings.mailgun_domain and settings.mailgun_sender:
        # Use Mailgun
        try:
            verification_link = f"{settings.frontend_url}/verify-email?token={verification_token}"

            response = requests.post(
                f"https://api.mailgun.net/v3/{settings.mailgun_domain}/messages",
                auth=("api", settings.mailgun_api_key),
                data={
                    "from": settings.mailgun_sender,
                    "to": [email],
                    "subject": "Verify your email address",
                    "text": f"""
        Hello,

        Thank you for signing up! Please click the link below to verify your email address:

        {verification_link}

        This link will expire in 24 hours.

        If you didn't create an account, please ignore this email.
        """
                }
            )

            if response.status_code == 200:
                logger.info(f"Verification email sent successfully to {email} via Mailgun")
            else:
                logger.error(f"Failed to send verification email via Mailgun: {response.status_code}, {response.text}")
                # Fallback to logging the token for debugging
                logger.info(f"Verification token for {email}: {verification_token}")

        except Exception as e:
            logger.error(f"Error sending verification email via Mailgun: {str(e)}")
            # Fallback to logging the token for debugging
            logger.info(f"Verification token for {email}: {verification_token}")

    elif settings.smtp_username and settings.smtp_password and settings.email_sender:
        # Use SMTP (supporting Unosend or other providers)
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = settings.email_sender
            msg['To'] = email
            msg['Subject'] = "Verify your email address"

            # Add Unosend tracking headers if available
            if hasattr(settings, 'unosend_track_opens') and settings.unosend_track_opens:
                msg['X-Unosend-Track-Opens'] = 'true'
            if hasattr(settings, 'unosend_track_clicks') and settings.unosend_track_clicks:
                msg['X-Unosend-Track-Clicks'] = 'true'
            if hasattr(settings, 'unosend_tags') and settings.unosend_tags:
                msg['X-Unosend-Tags'] = settings.unosend_tags

            # Create verification link
            verification_link = f"{settings.frontend_url}/verify-email?token={verification_token}"

            body = f"""
        Hello,

        Thank you for signing up! Please click the link below to verify your email address:

        {verification_link}

        This link will expire in 24 hours.

        If you didn't create an account, please ignore this email.
        """

            msg.attach(MIMEText(body, 'plain'))

            # Connect to SMTP server and send email
            # Use STARTTLS for secure connection (Unosend recommended)
            server = smtplib.SMTP(settings.smtp_host, settings.smtp_port)
            server.starttls()  # Enable encryption
            server.login(settings.smtp_username, settings.smtp_password)
            text = msg.as_string()
            server.sendmail(settings.email_sender, email, text)
            server.quit()

            logger.info(f"Verification email sent successfully to {email} via SMTP ({settings.smtp_host})")
        except Exception as e:
            logger.error(f"Failed to send verification email via SMTP: {str(e)}")
            # Log the token for debugging in case of failure
            logger.info(f"Verification token for {email}: {verification_token}")
    else:
        logger.warning(f"Email settings not configured, skipping verification email for {email}")
        # Still log the token for debugging purposes in development
        logger.info(f"Verification token for {email}: {verification_token}")
