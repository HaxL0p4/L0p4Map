if ! command -v nmap >/dev/null 2>&1; then
    if command -v apt >/dev/null 2>&1; then
        sudo apt update
        sudo apt install -y nmap
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -Sy --noconfirm nmap
    else
        echo "Package manager not yet supported."
        exit 1
    fi
fi

sudo python3 ui/app.py
