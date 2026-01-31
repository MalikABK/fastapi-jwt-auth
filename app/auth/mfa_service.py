# app/auth/mfa_service.py
# Service for multi-factor authentication functionality

import pyotp
import qrcode
from io import BytesIO
import base64
from sqlmodel import Session, select
from fastapi import HTTPException, status
from app.models.user import User
from app.auth.jwt import get_current_user
from app.auth.security import verify_password
from typing import Dict, Optional


def generate_totp_secret() -> str:
    """
    Generate a new TOTP secret for the user
    """
    return pyotp.random_base32()


def generate_qr_code(secret: str, email: str) -> str:
    """
    Generate QR code for TOTP setup
    """
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=email,
        issuer_name="FastAPI JWT Auth"
    )
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    
    # Encode the image to base64 for transmission
    img_str = base64.b64encode(buffer.getvalue()).decode()
    return f"data:image/png;base64,{img_str}"


def enable_mfa_for_user(
    *,
    session: Session,
    user_id: int,
    password: str,
    totp_code: str
) -> Dict[str, str]:
    """
    Enable MFA for a user after verifying their password and TOTP code
    """
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Verify the user's password
    if not verify_password(password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid password"
        )

    # Verify the TOTP code
    if not user.two_factor_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA setup not initiated. Generate a secret first."
        )

    totp = pyotp.TOTP(user.two_factor_secret)
    if not totp.verify(totp_code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid TOTP code"
        )

    # Enable MFA
    user.two_factor_enabled = True
    session.add(user)
    session.commit()

    return {"msg": "MFA enabled successfully"}


def disable_mfa_for_user(
    *,
    session: Session,
    user_id: int,
    password: str
) -> Dict[str, str]:
    """
    Disable MFA for a user after verifying their password
    """
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Verify the user's password
    if not verify_password(password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid password"
        )

    # Disable MFA
    user.two_factor_enabled = False
    user.two_factor_secret = None
    session.add(user)
    session.commit()

    return {"msg": "MFA disabled successfully"}


def generate_mfa_setup_info(
    *,
    session: Session,
    user_id: int
) -> Dict[str, str]:
    """
    Generate MFA setup information for a user
    """
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Generate a new secret
    secret = generate_totp_secret()
    user.two_factor_secret = secret
    session.add(user)
    session.commit()

    # Generate QR code
    qr_code = generate_qr_code(secret, user.email)

    return {
        "secret": secret,
        "qr_code": qr_code,
        "manual_entry_key": secret
    }


def verify_totp_code(
    *,
    session: Session,
    user_id: int,
    totp_code: str
) -> bool:
    """
    Verify a TOTP code for a user
    """
    user = session.get(User, user_id)
    if not user or not user.two_factor_secret:
        return False

    totp = pyotp.TOTP(user.two_factor_secret)
    return totp.verify(totp_code, valid_window=1)  # Allow 1 period before/after


def authenticate_with_mfa(
    *,
    session: Session,
    email: str,
    password: str,
    totp_code: str
) -> Dict[str, str]:
    """
    Authenticate a user with both password and TOTP code
    """
    from app.auth.service import authenticate_user

    # First, authenticate with username and password
    # This will raise an exception if credentials are invalid
    tokens = authenticate_user(session=session, email=email, password=password)

    # Get the user to check if MFA is enabled
    statement = select(User).where(User.email == email)
    user = session.exec(statement).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed"
        )

    # If MFA is enabled, verify the TOTP code
    if user.two_factor_enabled:
        if not totp_code:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="TOTP code required for this account"
            )

        totp = pyotp.TOTP(user.two_factor_secret)
        if not totp.verify(totp_code, valid_window=1):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid TOTP code"
            )

    return tokens