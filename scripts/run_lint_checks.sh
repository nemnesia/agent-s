#!/bin/bash

# Lint checks for the agent-s project

# Navigate to the project root
echo "Navigating to project root..."
cd "$(dirname "$0")/.." || exit 1

# Run flake8
echo "Running flake8..."
/home/harvestasya/.pyenv/versions/dev311/bin/python -m flake8 src/

# Run black
echo "Running black..."
/home/harvestasya/.pyenv/versions/dev311/bin/python -m black --check src/

# Run isort
echo "Running isort..."
/home/harvestasya/.pyenv/versions/dev311/bin/python -m isort --check-only src/

# Completion message
echo "Lint checks completed."
