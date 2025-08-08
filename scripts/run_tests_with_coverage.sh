#!/bin/bash

# Run tests with coverage

# Navigate to the project root
echo "Navigating to project root..."
cd "$(dirname "$0")/.." || exit 1

# Run tests with coverage
echo "Running tests with coverage..."
/home/harvestasya/.pyenv/versions/dev311/bin/python -m pytest --cov=src tests/

# Completion message
echo "Tests with coverage completed."
