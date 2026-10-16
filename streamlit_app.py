"""Streamlit Cloud entry point for the DANIP AI app.

Keep this deployment entry point intentionally thin: it starts the existing
application directly without the legacy DHIS2 OAuth gateway.
"""

from pathlib import Path
import runpy


APP_FILE = Path(__file__).with_name("app.py")

if not APP_FILE.is_file():
    raise FileNotFoundError(f"DANIP app file was not found: {APP_FILE}")

runpy.run_path(str(APP_FILE), run_name="__main__")
