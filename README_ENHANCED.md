# FastAPI JWT Authentication Service

**Production-ready JWT Authentication Service** showcasing expertise in FastAPI, SQLModel, Pytest, and security best practices. This project demonstrates a comprehensive, scalable authentication system built with modern Python technologies.

---

## 🚀 Key Features

### Core Functionality
- 🔐 **JWT Authentication**: Complete signup, login, refresh, and logout flow
- 🛡️ **Security-First Design**: Argon2 password hashing, token blacklisting, account lockout
- 🗄️ **SQLModel Integration**: Type-safe database models with SQLAlchemy and Pydantic
- 🧪 **Comprehensive Testing**: Full test coverage with Pytest and security-focused tests
- 🐳 **Docker Ready**: Production-ready containerization with multi-stage builds

### Enhanced Features
- 👤 **User Management**: Profile updates, password reset, email verification, account deletion
- 🔐 **Multi-Factor Authentication (MFA)**: TOTP-based 2FA with QR code generation
- 👥 **Role-Based Access Control (RBAC)**: Fine-grained permissions and role assignment
- 🔄 **Session Management**: Active session tracking and management
- 📊 **Audit Logging**: Comprehensive logging of authentication events
- 🗝️ **API Key Management**: Service-to-service authentication with scoped permissions
- ⚡ **Performance Optimizations**: Redis caching, connection pooling, rate limiting
- 📈 **Monitoring Ready**: Health checks and metrics endpoints

### Security Features
- **Argon2 Password Hashing**: Industry-leading password security
- **Token Blacklisting**: Immediate access token revocation on logout
- **Account Lockout**: Automatic protection after failed login attempts
- **Rate Limiting**: Brute-force protection on authentication endpoints
- **Generic Error Messages**: Prevention of user enumeration attacks
- **Input Validation**: Comprehensive validation and sanitization
- **MFA Support**: Two-factor authentication for enhanced security
- **Session Management**: Active session tracking and forced logout

### API Capabilities
- **Protected Routes**: JWT-based access control with role-based permissions
- **Refresh Tokens**: Long-lived tokens for seamless user experience
- **Auto Documentation**: Interactive API docs via Swagger UI
- **Health Checks**: Production-ready monitoring endpoints
- **API Key Authentication**: Service-to-service authentication
- **Fine-Grained Permissions**: Resource-level access controls

---

## 🏗️ Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │────│   FastAPI       │────│   PostgreSQL    │
│   (Client)      │    │   Authentication│    │   (Database)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                             │
                    ┌─────────────────┐
                    │   Redis         │
                    │   (Cache & Rate │
                    │    Limiting)    │
                    └─────────────────┘
```

**Technology Stack:**
- **Framework**: FastAPI with Pydantic v2
- **Database**: SQLModel (SQLAlchemy + Pydantic)
- **Authentication**: JWT with refresh tokens
- **Security**: Argon2, rate limiting with slowapi, MFA with pyotp
- **Caching**: Redis for session management and rate limiting
- **Testing**: Pytest with comprehensive test suite
- **Containerization**: Docker & Docker Compose
- **API Documentation**: Automatic OpenAPI/Swagger generation

---

## 💼 Portfolio Value

This project demonstrates advanced skills in:
- **Modern Python Development**: Async programming, type hints, dependency injection
- **Security Implementation**: Authentication, authorization, threat mitigation
- **Database Design**: SQLModel ORM, transaction management, migrations
- **Testing Strategy**: Unit, integration, and security-focused tests
- **DevOps Practices**: Docker containerization, CI/CD pipeline
- **API Design**: RESTful endpoints, proper error handling, documentation
- **Performance Optimization**: Redis caching, connection pooling, rate limiting
- **Enterprise Features**: RBAC, audit logging, API key management

---

## 🛠️ Local Development

### Prerequisites
- Docker and Docker Compose
- Python 3.12+
- UV package manager

### Quick Start with Docker (Recommended)
```bash
# Clone the repository
git clone <repository-url>
cd fastapi-jwt-auth

# Build and run with Docker Compose
docker compose up --build

# Access the services:
# - API: http://localhost:8000
# - API Docs: http://localhost:8000/docs
# - Health Check: http://localhost:8000/health
```

### Development Setup
```bash
# Install dependencies with uv
uv sync

# Activate virtual environment
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Run the application
uv run uvicorn main:app --reload --port 8000

# Run tests
uv run pytest

# Check code quality
uv run pytest tests/ -v
```

### Environment Variables
Create a `.env` file using `.env.example` as reference:

```bash
cp .env.example .env
# Edit .env with your specific configuration
```

### Redis Configuration (Optional)
For enhanced performance and rate limiting, configure Redis:
```
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0
```

---

## 🧪 Testing & Quality

### Test Suite
```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=app --cov-report=html

# Run specific test file
uv run pytest tests/test_auth_security.py -v
```

### API Endpoints
| Endpoint | Method | Auth Required | Description |
|----------|--------|---------------|-------------|
| `/auth/signup` | POST | None | Create new user account |
| `/auth/token` | POST | None | Login and get JWT tokens |
| `/auth/refresh` | POST | None | Get new access token |
| `/auth/logout` | POST | None | Revoke refresh token |
| `/users/me` | GET | JWT | Get current user profile |
| `/users/me` | PATCH | JWT | Update current user profile |
| `/mfa/setup` | POST | JWT | Setup MFA for user |
| `/mfa/enable` | POST | JWT | Enable MFA for user |
| `/sessions/active` | GET | JWT | Get active sessions |
| `/api-keys/create` | POST | JWT | Create new API key |
| `/api-keys/my-keys` | GET | JWT | Get user's API keys |
| `/audit/logs/my-activity` | GET | JWT | Get user's audit trail |
| `/tasks/me` | GET | JWT | Get current user info |
| `/tasks/admin` | GET | JWT (Admin) | Admin-only route |
| `/health` | GET | None | Health check endpoint |

---

## 🚀 Deployment

### Production Deployment
```bash
# Build and deploy with Docker Compose
docker compose -f docker-compose.yml up -d

# Monitor logs
docker compose logs -f
```

### Environment Configuration
The application supports different environments (development, staging, production) with proper configuration management for secrets and database connections.

### Redis Setup for Production
For production deployments, configure a dedicated Redis instance:
```
REDIS_HOST=redis.yourdomain.com
REDIS_PORT=6379
REDIS_PASSWORD=your_secure_password
REDIS_DB=0
```

---

## 📊 Security Benchmarks

- ✅ **Password Strength**: Enforced with Argon2 hashing
- ✅ **Rate Limiting**: Prevents brute force attacks
- ✅ **Account Lockout**: Automatic after 5 failed attempts
- ✅ **Token Blacklisting**: Immediate revocation capability
- ✅ **Input Validation**: Comprehensive validation layer
- ✅ **Error Handling**: Generic messages to prevent information disclosure
- ✅ **MFA Support**: Two-factor authentication for enhanced security
- ✅ **Session Management**: Active session tracking and forced logout
- ✅ **Audit Trail**: Comprehensive logging of all authentication events

---

## 📈 API Key Management

The service includes a complete API key management system:
- Create scoped API keys for service-to-service authentication
- Revoke individual or all API keys
- Rotate API keys securely
- Rate limiting per API key
- Audit trail for all API key operations

### Creating an API Key
```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  "http://localhost:8000/api-keys/create?name=MyApp&scopes=read&scopes=write&rate_limit=1000"
```

---

## 🛡️ Multi-Factor Authentication (MFA)

The service includes TOTP-based MFA:
- QR code generation for easy setup
- Time-based one-time passwords
- Ability to enable/disable MFA per user
- Separate login endpoint for MFA-enabled accounts

### Setting up MFA
1. Call `/mfa/setup` to generate QR code
2. Scan the QR code with an authenticator app (Google Authenticator, Authy, etc.)
3. Call `/mfa/enable` with the current TOTP code and your password

---

## 📋 Postman Collection

A complete Postman collection is included in `FastAPI-JWT-Auth-Postman-Collection.json` for easy API testing and exploration.

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Run the test suite (`uv run pytest`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🎯 Business Impact

This authentication service represents a production-ready solution that:
- Reduces development time for new projects by providing a ready authentication system
- Ensures security best practices are consistently applied
- Scales horizontally with modern container orchestration
- Provides comprehensive audit trails and monitoring capabilities
- Supports rapid prototyping and MVP development
- Includes enterprise-grade features like RBAC, MFA, and API key management