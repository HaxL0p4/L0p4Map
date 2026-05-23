#!/bin/bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BRANCH="main"

_install_pkg() {
    local pkg="$1"
    if command -v apt >/dev/null 2>&1; then
        apt-get install -y -qq "$pkg"
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --noconfirm --noprogressbar "$pkg" >/dev/null
    else
        echo "error: unsupported package manager — install '$pkg' manually" >&2
        exit 1
    fi
}

if ! command -v nmap >/dev/null 2>&1; then
    echo "installing nmap..."
    _install_pkg nmap
fi

_ensure_pyqt6_webengine() {
    if python3 -c "from PyQt6.QtWebEngineWidgets import QWebEngineView" >/dev/null 2>&1; then
        return
    fi
    echo "installing PyQt6-WebEngine..."
    if command -v pacman >/dev/null 2>&1; then
        _install_pkg python-pyqt6-webengine
    else
        _install_pkg python3-pyqt6.qtwebengine
    fi
}

_ensure_pyqt6() {
    if command -v pacman >/dev/null 2>&1; then
        pacman -Qi python-pyqt6 >/dev/null 2>&1 || _install_pkg python-pyqt6
    else
        dpkg -s python3-pyqt6.qtsvg >/dev/null 2>&1 || _install_pkg python3-pyqt6.qtsvg
    fi
}

CLI_ONLY=false
for arg in "$@"; do
    case "$arg" in
        scan|--version|-V|--help|-h) CLI_ONLY=true ;;
    esac
done

if [ "$CLI_ONLY" = false ]; then
    _ensure_pyqt6_webengine
    _ensure_pyqt6
fi

cd "$REPO_DIR"

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git fetch origin "$BRANCH" >/dev/null 2>&1 || true
    LOCAL=$(git rev-parse HEAD 2>/dev/null || echo "")
    REMOTE=$(git rev-parse "origin/$BRANCH" 2>/dev/null || echo "")
    if [ -n "$LOCAL" ] && [ -n "$REMOTE" ] && [ "$LOCAL" != "$REMOTE" ]; then
        echo "update available — pulling..."
        git pull origin "$BRANCH" >/dev/null 2>&1
        echo "updated. restart to apply: $0 $*"
        exit 0
    fi
fi

PYTHON="$(command -v python3)"
[ -f "$REPO_DIR/venv/bin/python3" ] && PYTHON="$REPO_DIR/venv/bin/python3"

exec sudo -E "$PYTHON" "$REPO_DIR/__main__.py" "$@"
