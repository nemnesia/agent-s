#!/bin/bash

# Build a zipapp for the agent-s project

# Navigate to the project root
echo "Navigating to project root..."
cd "$(dirname "$0")/.." || exit 1

# Create the zipapp
echo "Building zipapp..."
/home/harvestasya/.pyenv/versions/dev311/bin/python -m zipapp src -o agent-s.pyz

# Completion message
echo "Zipapp created: agent-s.pyz"
