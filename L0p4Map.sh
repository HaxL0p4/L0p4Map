#!/bin/bash
REPO_DIR="$(pwd)"
BRANCH="main"

OS="$(uname -s)"

install_pkg() {
    local pkg_apt="$1"
    local pkg_pacman="$2"
    local pkg_brew="$3"

    if [ "$OS" = "Darwin" ]; then
        brew install "$pkg_brew" --quiet
    elif command -v apt >/dev/null 2>&1; then
        sudo apt update -qq
        sudo apt install -y -qq "$pkg_apt"
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -Sy --noconfirm --noprogressbar "$pkg_pacman" >/dev/null
    else
        echo "Package manager not supported."
        exit 1
    fi
}

if ! command -v nmap >/dev/null 2>&1; then
    echo "Installing nmap..."
    install_pkg nmap nmap nmap
fi

if ! python3 -c "from PyQt6.QtWebEngineWidgets import QWebEngineView" >/dev/null 2>&1; then
    echo "Installing PyQt6-WebEngine..."
    if [ "$OS" = "Darwin" ]; then
        pip3 install PyQt6 PyQt6-WebEngine --quiet
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -Sy --noconfirm --noprogressbar python-pyqt6-webengine >/dev/null
    elif command -v apt >/dev/null 2>&1; then
        sudo apt install -y -qq python3-pyqt6.qtwebengine
    else
        echo "Package manager not supported."
        exit 1
    fi
fi

if ! python3 -c "from PyQt6.QtSvg import QSvgRenderer" >/dev/null 2>&1; then
    echo "Installing PyQt6-Qt6Svg..."
    if [ "$OS" = "Darwin" ]; then
        pip3 install PyQt6 --quiet
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -Sy --noconfirm --noprogressbar python-pyqt6 >/dev/null
    elif command -v apt >/dev/null 2>&1; then
        sudo apt install -y -qq python3-pyqt6.qtsvg
    else
        echo "Package manager not supported."
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

PYTHON=$(command -v python3)
[ -f "$REPO_DIR/venv/bin/python3" ] && PYTHON="$REPO_DIR/venv/bin/python3"
sudo -E "$PYTHON" ui/app.py
