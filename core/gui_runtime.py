"""Configure Qt before loading GUI dependencies or creating QApplication."""

import os


def configure_gui_environment():
    # On Windows, Qt must select its compatible graphics backend. Disabling
    # both GPU and software rendering breaks WebEngine context initialization.
    if os.name == "nt":
        flags = "--no-sandbox"
    else:
        flags = "--no-sandbox --disable-gpu --disable-software-rasterizer"
    os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", flags)
    os.environ.setdefault("QTWEBENGINE_DISABLE_SANDBOX", "1")
