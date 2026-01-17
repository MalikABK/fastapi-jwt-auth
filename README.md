# FastAPI JWT Authentication Service

This project is a **production-ready authentication backend** built with **FastAPI**, implementing secure **JWT-based authentication** for modern API-driven applications.

It provides user signup, login, and protected endpoints using industry-standard security practices. The service is fully **Dockerized** and designed to be **scalable, stateless, and cloud-ready**, making it suitable for real-world backend systems and microservices architectures.

---

## Key Features

- User signup and login
- JWT access token authentication
- Secure password hashing
- Protected API routes
- PostgreSQL database integration
- Docker & Docker Compose support
- Auto-generated API documentation (`/docs`)

---

## Why This Project Exists

Most modern applications require a secure, stateless authentication system that can scale easily across environments. This project demonstrates how to build such a system using FastAPI, following clean architecture and production-grade practices.

It is intended to serve as:

- A reusable authentication service
- A reference implementation for FastAPI security
- A deployable backend component for real projects

---

## Tech Stack

| Layer | Technology |
|------|-----------|
| API Framework | FastAPI |
| Language | Python 3.12 |
| Authentication | JWT (JSON Web Tokens) |
| ORM | SQLModel |
| Database | PostgreSQL |
| Server | Uvicorn |
| Containers | Docker, Docker Compose |

---

## What Success Looks Like

- The service runs using `docker compose up`
- Users can sign up and log in
- JWT tokens protect secured endpoints
- The API is accessible via Swagger UI

---

## How to Run Locally

```bash
docker compose up --build
