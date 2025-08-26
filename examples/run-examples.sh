#!/bin/bash

# HackAI Examples Runner
# This script helps run different examples without conflicts

echo "🚀 HackAI Examples Runner"
echo "========================="
echo ""
echo "Available examples:"
echo "1. Fraud Detection Demo"
echo "2. Ollama Complete Example"
echo "3. Exit"
echo ""

read -p "Select an example (1-3): " choice

case $choice in
    1)
        echo ""
        echo "🛡️ Running Fraud Detection Demo..."
        echo "Make sure the fraud detection service is running on port 8080"
        echo ""
        cd fraud-demo && go run main.go
        ;;
    2)
        echo ""
        echo "🤖 Running Ollama Complete Example..."
        echo "Make sure Ollama is installed and running"
        echo ""
        cd olama-complete-example && go run main.go
        ;;
    3)
        echo "Goodbye!"
        exit 0
        ;;
    *)
        echo "Invalid choice. Please select 1-3."
        exit 1
        ;;
esac