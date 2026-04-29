"""PyInstaller runtime hook: point pytesseract at the bundled tesseract.exe."""
import os
import sys
from pathlib import Path

if hasattr(sys, "_MEIPASS"):
    bundled = Path(sys._MEIPASS) / "tesseract" / "tesseract.exe"
    if bundled.exists():
        os.environ["PATH"] = str(bundled.parent) + os.pathsep + os.environ.get("PATH", "")
        tessdata = bundled.parent / "tessdata"
        if tessdata.exists():
            os.environ["TESSDATA_PREFIX"] = str(tessdata)
        try:
            import pytesseract
            pytesseract.pytesseract.tesseract_cmd = str(bundled)
        except ImportError:
            pass
