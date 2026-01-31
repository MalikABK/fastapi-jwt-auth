# app/auth/user_management_service.py
# Service for extended user management functionality

import logging
from sqlmodel import Session, select, SQLModel, Field
from fastapi import HTTPException, status
from app.models.user import User, UserPublic, UserUpdate
from datetime import datetime, timedelta
from typing import Optional
from pydantic import EmailStr, field_validator
import re
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from enum import Enum


class UserProfileUpdate(SQLModel):
    full_name: Optional[str] = None
    phone_number: Optional[str] = None
    avatar_url: Optional[str] = None
    bio: Optional[str] = None

    @field_validator('phone_number')
    @classmethod
    def validate_phone_number(cls, v):
        if v is not None:
            # Simple validation - could be enhanced based on requirements
            v = v.strip()
            if len(v) < 10 or len(v) > 15:
                raise ValueError('Phone number must be between 10 and 15 characters')
        return v

    @field_validator('bio')
    @classmethod
    def validate_bio(cls, v):
        if v is not None:
            v = v.strip()
            if len(v) > 500:
                raise ValueError('Bio must not exceed 500 characters')
        return v


class PasswordResetRequest(SQLModel):
    email: EmailStr


class PasswordReset(SQLModel):
    token: str
    new_password: str

    @field_validator('new_password')
    @classmethod
    def validate_new_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain at least one special character')
        return v


class EmailVerificationRequest(SQLModel):
    token: str


class AccountDeletionRequest(SQLModel):
    password: str


# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def update_user_profile(
    *, 
    session: Session, 
    user_id: int, 
    profile_update: UserProfileUpdate
) -> UserPublic:
    """
    Update user profile information
    """
    logger.info(f"Updating profile for user ID: {user_id}")
    
    user = session.get(User, user_id)
    if not user:
        logger.warning(f"User not found for ID: {user_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Update allowed fields
    update_data = profile_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(user, field, value)
    
    user.updated_at = datetime.utcnow()
    
    try:
        session.add(user)
        session.commit()
        session.refresh(user)
        logger.info(f"Successfully updated profile for user ID: {user_id}")
        
        return user
    except Exception as e:
        session.rollback()
        logger.error(f"Failed to update user profile: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to update user profile: {str(e)}"
        )


def request_password_reset(*, session: Session, request: PasswordResetRequest) -> dict:
    """
    Request password reset - creates a reset token and sends email
    """
    logger.info(f"Password reset requested for email: {request.email}")
    
    statement = select(User).where(User.email == request.email)
    user = session.exec(statement).first()
    
    if not user:
        # Return success even if user doesn't exist to prevent email enumeration
        logger.info(f"Password reset request processed for email: {request.email}")
        return {"msg": "If an account with this email exists, a reset link has been sent"}
    
    # Generate reset token
    reset_token = secrets.token_urlsafe(32)
    reset_token_expires = datetime.utcnow() + timedelta(
        minutes=60  # Using default value instead of settings constant for now
    )
    
    # Store reset token in user record
    user.password_reset_token = reset_token
    user.password_reset_expires = reset_token_expires
    
    try:
        session.add(user)
        session.commit()
        
        # Send email with reset link (mock implementation)
        # In a real application, you would send an actual email here
        logger.info(f"Password reset token generated for user ID: {user.id}")
        send_password_reset_email(user.email, reset_token)
        
        return {"msg": "If an account with this email exists, a reset link has been sent"}
    except Exception as e:
        session.rollback()
        logger.error(f"Failed to process password reset request: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process password reset request"
        )


def reset_password(*, session: Session, reset_data: PasswordReset) -> dict:
    """
    Reset password using the provided token
    """
    logger.info(f"Processing password reset with token")
    
    statement = select(User).where(
        User.password_reset_token == reset_data.token
    )
    user = session.exec(statement).first()
    
    if not user:
        logger.warning("Invalid or expired password reset token")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token"
        )
    
    if user.password_reset_expires < datetime.utcnow():
        logger.warning("Expired password reset token")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reset token has expired"
        )
    
    # Hash the new password
    from app.auth.security import hash_password
    hashed_password = hash_password(reset_data.new_password)
    
    # Update user password and clear reset token
    user.hashed_password = hashed_password
    user.password_reset_token = None
    user.password_reset_expires = None
    
    try:
        session.add(user)
        session.commit()
        
        logger.info(f"Password successfully reset for user ID: {user.id}")
        return {"msg": "Password has been reset successfully"}
    except Exception as e:
        session.rollback()
        logger.error(f"Failed to reset password: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to reset password"
        )


def verify_email(*, session: Session, verification_data: EmailVerificationRequest) -> dict:
    """
    Verify user email using the provided token
    """
    logger.info(f"Processing email verification")
    
    statement = select(User).where(
        User.email_verification_token == verification_data.token
    )
    user = session.exec(statement).first()
    
    if not user:
        logger.warning("Invalid email verification token")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification token"
        )
    
    # Check if token has expired
    if user.email_verification_expires and user.email_verification_expires < datetime.utcnow():
        logger.warning("Expired email verification token")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification token has expired"
        )
    
    # Verify the email
    user.is_verified = True
    user.email_verification_token = None
    user.email_verification_expires = None
    
    try:
        session.add(user)
        session.commit()
        
        logger.info(f"Email verified for user ID: {user.id}")
        return {"msg": "Email has been verified successfully"}
    except Exception as e:
        session.rollback()
        logger.error(f"Failed to verify email: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify email"
        )


def delete_account(*, session: Session, user_id: int, deletion_request: AccountDeletionRequest) -> dict:
    """
    Delete user account after verifying password
    """
    logger.info(f"Processing account deletion for user ID: {user_id}")
    
    user = session.get(User, user_id)
    if not user:
        logger.warning(f"User not found for ID: {user_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Verify the provided password
    from app.auth.security import verify_password
    if not verify_password(deletion_request.password, user.hashed_password):
        logger.warning(f"Invalid password for account deletion by user ID: {user_id}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid password"
        )
    
    try:
        # Delete the user (this will cascade delete related records if configured)
        session.delete(user)
        session.commit()
        
        logger.info(f"Account deleted successfully for user ID: {user_id}")
        return {"msg": "Account has been deleted successfully"}
    except Exception as e:
        session.rollback()
        logger.error(f"Failed to delete account: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete account"
        )


def generate_email_verification_token(*, session: Session, user_id: int) -> dict:
    """
    Generate and send email verification token
    """
    logger.info(f"Generating email verification token for user ID: {user_id}")
    
    user = session.get(User, user_id)
    if not user:
        logger.warning(f"User not found for ID: {user_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Generate verification token
    verification_token = secrets.token_urlsafe(32)
    verification_expires = datetime.utcnow() + timedelta(hours=24)  # 24-hour expiry
    
    user.email_verification_token = verification_token
    user.email_verification_expires = verification_expires
    
    try:
        session.add(user)
        session.commit()
        
        # Send verification email (mock implementation)
        logger.info(f"Email verification token generated for user ID: {user_id}")
        send_verification_email(user.email, verification_token)
        
        return {"msg": "Verification email has been sent"}
    except Exception as e:
        session.rollback()
        logger.error(f"Failed to generate verification token: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate verification token"
        )


def send_password_reset_email(email: str, reset_token: str):
    """
    Function to send password reset email using either Resend, Mailgun, or SMTP
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

            reset_link = f"{settings.frontend_url}/reset-password?token={reset_token}"

            params = {
                "from": settings.resend_sender,
                "to": [email],
                "subject": "Password Reset Request",
                "html": f"""
        <p>Hello,</p>
        <p>You have requested to reset your password. Please click the link below to reset your password:</p>
        <p><a href="{reset_link}">Reset Password</a></p>
        <p>This link will expire in 60 minutes.</p>
        <p>If you didn't request a password reset, please ignore this email.</p>
        """,
                "text": f"""
        Hello,

        You have requested to reset your password. Please click the link below to reset your password:

        {reset_link}

        This link will expire in 60 minutes.

        If you didn't request a password reset, please ignore this email.
        """
            }

            response = resend.Emails.send(params)

            logger.info(f"Password reset email sent successfully to {email} via Resend with ID: {response['id']}")
        except Exception as e:
            logger.error(f"Error sending password reset email via Resend: {str(e)}")
            # Fallback to logging the token for debugging
            logger.info(f"Password reset token for {email}: {reset_token}")

    elif settings.mailgun_api_key and settings.mailgun_domain and settings.mailgun_sender:
        # Use Mailgun
        try:
            reset_link = f"{settings.frontend_url}/reset-password?token={reset_token}"

            response = requests.post(
                f"https://api.mailgun.net/v3/{settings.mailgun_domain}/messages",
                auth=("api", settings.mailgun_api_key),
                data={
                    "from": settings.mailgun_sender,
                    "to": [email],
                    "subject": "Password Reset Request",
                    "text": f"""
        Hello,

        You have requested to reset your password. Please click the link below to reset your password:

        {reset_link}

        This link will expire in 60 minutes.

        If you didn't request a password reset, please ignore this email.
        """
                }
            )

            if response.status_code == 200:
                logger.info(f"Password reset email sent successfully to {email} via Mailgun")
            else:
                logger.error(f"Failed to send password reset email via Mailgun: {response.status_code}, {response.text}")
                # Fallback to logging the token for debugging
                logger.info(f"Password reset token for {email}: {reset_token}")

        except Exception as e:
            logger.error(f"Error sending password reset email via Mailgun: {str(e)}")
            # Fallback to logging the token for debugging
            logger.info(f"Password reset token for {email}: {reset_token}")

    elif settings.smtp_username and settings.smtp_password and settings.email_sender:
        # Use SMTP
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = settings.email_sender
            msg['To'] = email
            msg['Subject'] = "Password Reset Request"

            # Create reset link
            reset_link = f"{settings.frontend_url}/reset-password?token={reset_token}"

            body = f"""
        Hello,

        You have requested to reset your password. Please click the link below to reset your password:

        {reset_link}

        This link will expire in 60 minutes.

        If you didn't request a password reset, please ignore this email.
        """

            msg.attach(MIMEText(body, 'plain'))

            # Connect to SMTP server and send email
            server = smtplib.SMTP(settings.smtp_host, settings.smtp_port)
            server.starttls()
            server.login(settings.smtp_username, settings.smtp_password)
            text = msg.as_string()
            server.sendmail(settings.email_sender, email, text)
            server.quit()

            logger.info(f"Password reset email sent successfully to {email} via SMTP")
        except Exception as e:
            logger.error(f"Failed to send password reset email via SMTP: {str(e)}")
            # Log the token for debugging in case of failure
            logger.info(f"Password reset token for {email}: {reset_token}")
    else:
        logger.warning(f"Email settings not configured, skipping password reset email for {email}")
        # Still log the token for debugging purposes in development
        logger.info(f"Password reset token for {email}: {reset_token}")


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
        # Use SMTP
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = settings.email_sender
            msg['To'] = email
            msg['Subject'] = "Verify your email address"

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
            server = smtplib.SMTP(settings.smtp_host, settings.smtp_port)
            server.starttls()
            server.login(settings.smtp_username, settings.smtp_password)
            text = msg.as_string()
            server.sendmail(settings.email_sender, email, text)
            server.quit()

            logger.info(f"Verification email sent successfully to {email} via SMTP")
        except Exception as e:
            logger.error(f"Failed to send verification email via SMTP: {str(e)}")
            # Log the token for debugging in case of failure
            logger.info(f"Verification token for {email}: {verification_token}")
    else:
        logger.warning(f"Email settings not configured, skipping verification email for {email}")
        # Still log the token for debugging purposes in development
        logger.info(f"Verification token for {email}: {verification_token}")