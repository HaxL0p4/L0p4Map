import ctypes
import os


def require_admin():
    """Require Administrator on Windows or root on Unix before network operations."""
    if os.name == "nt":
        try:
            elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            elevated = False
        message = "Administrator privileges required (run PowerShell or CMD as Administrator)."
    else:
        elevated = os.getuid() == 0
        message = "Root privileges required (run with sudo)."

    if not elevated:
        raise PermissionError(message)
