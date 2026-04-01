#!/bin/bash
REPO_DIR="$(pwd)"
BRANCH="main"

if ! command -v nmap >/dev/null 2>&1; then
    if command -v apt >/dev/null 2>&1; then
        sudo apt update -qq
        sudo apt install -y -qq nmap
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -Sy --noconfirm --noprogressbar nmap >/dev/null
    else
        echo "Package manager not yet supported."
        exit 1
    fi
fi

if ! python3 -c "from PyQt6.QtWebEngineWidgets import QWebEngineView" >/dev/null 2>&1; then
    echo "Installing PyQt6-WebEngine..."
    if command -v pacman >/dev/null 2>&1; then
        sudo pacman -Sy --noconfirm --noprogressbar python-pyqt6-webengine >/dev/null
    elif command -v apt >/dev/null 2>&1; then
        sudo apt install -y -qq python3-pyqt6.qtwebengine
    else
        echo "Package manager not yet supported."
        exit 1
    fi
fi

cd "$REPO_DIR" || exit 1

git fetch origin "$BRANCH" >/dev/null 2>&1
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse "origin/$BRANCH")

if [ "$LOCAL" != "$REMOTE" ]; then
    echo "Update found, pulling latest changes..."
    git pull origin "$BRANCH" >/dev/null 2>&1
    echo "Done! Please restart the script to apply the updates: $0"
    exit 0
fi

sudo python3 ui/app.py
