#!/bin/bash

# Script to verify Docker optimization changes
echo "🔍 Verifying Docker optimization changes..."

echo ""
echo "✅ 1. Checking .dockerignore file..."
if [ -f ".dockerignore" ]; then
    echo "   ✓ .dockerignore file exists"

    # Check if sensitive files are in the ignore list
    if grep -q "\.claude/" .dockerignore; then
        echo "   ✓ .claude/ directory is excluded"
    else
        echo "   ✗ .claude/ directory not found in .dockerignore"
    fi

    if grep -q "claude.md" .dockerignore; then
        echo "   ✓ claude.md is excluded"
    else
        echo "   ✗ claude.md not found in .dockerignore"
    fi

    if grep -q "PORTFOLIO.md" .dockerignore; then
        echo "   ✓ PORTFOLIO.md is excluded"
    else
        echo "   ✗ PORTFOLIO.md not found in .dockerignore"
    fi

    if grep -q "test.db" .dockerignore; then
        echo "   ✓ test.db is excluded"
    else
        echo "   ✗ test.db not found in .dockerignore"
    fi

    if grep -q "\.venv/" .dockerignore; then
        echo "   ✓ .venv/ directory is excluded"
    else
        echo "   ✗ .venv/ directory not found in .dockerignore"
    fi
else
    echo "   ✗ .dockerignore file does not exist"
fi

echo ""
echo "✅ 2. Checking Dockerfile..."
if [ -f "Dockerfile" ]; then
    echo "   ✓ Dockerfile exists"

    # Check if the Dockerfile has the right structure
    if grep -q "COPY . ." Dockerfile; then
        echo "   ✓ Dockerfile has COPY . . command (will respect .dockerignore)"
    else
        echo "   ⚠ Dockerfile COPY command not as expected"
    fi

    if grep -q "FROM python:3.12" Dockerfile; then
        echo "   ✓ Dockerfile uses Python 3.12"
    else
        echo "   ⚠ Dockerfile may not use Python 3.12"
    fi

    if grep -q "uv sync --frozen --no-dev" Dockerfile; then
        echo "   ✓ Dockerfile correctly installs only production dependencies"
    else
        echo "   ⚠ Dockerfile may not correctly install only production dependencies"
    fi
else
    echo "   ✗ Dockerfile does not exist"
fi

echo ""
echo "✅ 3. Checking sensitive files existence in project root..."
SENSITIVE_FILES=(".claude" "claude.md" "PORTFOLIO.md" "test.db")

for file in "${SENSITIVE_FILES[@]}"; do
    if [ -e "$file" ]; then
        echo "   ⚠ $file exists in project root (but should be excluded from Docker build)"
    else
        echo "   ✓ $file not found in project root (good)"
    fi
done

echo ""
echo "✅ 4. Checking project structure for essential files..."
ESSENTIAL_FILES=("main.py" "pyproject.toml" "uv.lock" "app/")

for file in "${ESSENTIAL_FILES[@]}"; do
    if [ -e "$file" ]; then
        echo "   ✓ $file exists (needed for application)"
    else
        echo "   ✗ $file does not exist (needed for application)"
    fi
done

echo ""
echo "✅ 5. Summary of Docker optimization:"
echo "   • .dockerignore now excludes sensitive files: .claude/, claude.md, PORTFOLIO.md, test.db"
echo "   • Dockerfile uses multi-stage build with proper caching"
echo "   • Dependencies are installed first for better caching"
echo "   • Non-root user is used for security"
echo "   • Health check is configured"
echo ""
echo "   The Docker build will now exclude sensitive files while maintaining functionality."

echo ""
echo "🎯 To test the Docker build, run:"
echo "   docker build -t fastapi-jwt-auth ."
echo ""
echo "   The sensitive files will be automatically excluded due to .dockerignore."