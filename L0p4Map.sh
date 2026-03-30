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

cd "$REPO_DIR" || exit 1
git fetch origin "$BRANCH" >/dev/null 2>&1

LOCAL=$(git rev-parse "$BRANCH")
REMOTE=$(git rev-parse "origin/$BRANCH")

if [ "$LOCAL" != "$REMOTE" ]; then
    echo "Updating..."
    git pull origin "$BRANCH" >/dev/null 2>&1
    echo "Updated!"
fi

sudo python3 ui/app.py
