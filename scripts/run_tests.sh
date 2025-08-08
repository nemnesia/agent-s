#!/bin/bash

# Run tests without coverage

# Navigate to the project root
echo "Navigating to project root..."
cd "$(dirname "$0")/.." || exit 1

# Run tests
echo "Running tests..."
/home/harvestasya/.pyenv/versions/dev311/bin/python -m pytest tests/

# Completion message
echo "Tests completed."
