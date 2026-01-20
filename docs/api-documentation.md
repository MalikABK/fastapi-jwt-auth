# API Documentation

This document provides detailed information about the FastAPI JWT Authentication Service API endpoints, request/response formats, and usage examples.

## Base URL
```
http://localhost:8000  # Development
https://yourdomain.com # Production
```

## Authentication

The API uses JWT (JSON Web Token) authentication. After successful login, you'll receive both access and refresh tokens.

- **Access Token**: Used for authenticating requests to protected endpoints (expires in 30 minutes by default)
- **Refresh Token**: Used to get new access tokens without re-login (expires in 7 days by default)

## Endpoints

### Authentication Endpoints

#### POST /auth/signup
Create a new user account.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "full_name": "John Doe"
}
```

**Validation Rules:**
- Password must be at least 8 characters
- Password must contain uppercase, lowercase, digit, and special character
- Email must be in valid format
- Full name must not exceed 100 characters

**Response (201 Created):**
```json
{
  "id": 1,
  "email": "user@example.com",
  "full_name": "John Doe",
  "is_active": true,
  "is_superuser": false,
  "created_at": "2024-01-18T10:30:00Z"
}
```

**Errors:**
- 422: Validation error (invalid input)
- 400: Email already registered

---

#### POST /auth/token
Authenticate user and receive JWT tokens.

**Request (Form Data):**
```
username: user@example.com
password: SecurePassword123!
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer"
}
```

**Errors:**
- 401: Invalid credentials
- 422: Missing form data

---

#### POST /auth/refresh
Get a new access token using a refresh token.

**Request Body:**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer"
}
```

**Errors:**
- 401: Invalid refresh token
- 401: Token revoked

---

#### POST /auth/logout
Revoke the refresh token and optionally blacklist the access token.

**Request Body:**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

**Headers (Optional):**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

**Response (200 OK):**
```json
{
  "msg": "Logged out successfully"
}
```

**Errors:**
- 401: Invalid token

---

### Protected Endpoints

#### GET /tasks/me
Get information about the currently authenticated user.

**Headers:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

**Response (200 OK):**
```json
{
  "id": 1,
  "email": "user@example.com",
  "full_name": "John Doe",
  "is_active": true,
  "is_superuser": false
}
```

**Errors:**
- 401: Invalid or expired token

---

#### GET /tasks/admin
Get information about the current user (admin only).

**Headers:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

**Response (200 OK):**
```json
{
  "id": 1,
  "email": "admin@example.com",
  "full_name": "Admin User",
  "is_active": true,
  "is_superuser": true
}
```

**Errors:**
- 401: Invalid or expired token
- 403: Insufficient privileges (not an admin)

---

### Health Check

#### GET /health
Check if the service is running.

**Response (200 OK):**
```json
{
  "status": "healthy",
  "service": "fastapi-jwt-auth"
}
```

## Error Responses

The API returns standard HTTP status codes:

- 200: Success
- 201: Created
- 400: Bad Request
- 401: Unauthorized
- 403: Forbidden
- 404: Not Found
- 422: Validation Error
- 429: Too Many Requests (rate limited)

Common error response format:
```json
{
  "detail": "Error message"
}
```

## Rate Limiting

The API implements rate limiting to prevent abuse:

- `/auth/signup`: 5 requests per minute per IP
- `/auth/token`: 10 requests per minute per IP
- `/auth/refresh`: 30 requests per minute per IP
- `/auth/logout`: 10 requests per minute per IP

When rate limit is exceeded, you'll receive a 429 status code.

## Security Features

- Passwords are hashed using Argon2
- JWT tokens include expiration and type validation
- Account lockout after 5 failed login attempts (for 30 minutes)
- Generic error messages to prevent user enumeration
- Input validation and sanitization
- Security headers for common vulnerabilities