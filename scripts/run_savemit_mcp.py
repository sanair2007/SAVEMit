"""Bootstrap SAVEMit and run its stdio MCP server.

This script uses only the Python standard library so a plugin installation can
create its own isolated environment before SAVEMit's dependencies exist.
"""

import os
import subprocess
import sys
from pathlib import Path


def run(command):
    subprocess.run(command, check=True, stdout=sys.stderr, stderr=sys.stderr)


def main():
    repository_root = Path(__file__).resolve().parents[1]
    environment_root = repository_root / ".savemit-plugin-venv"
    python = environment_root / (
        "Scripts/python.exe" if os.name == "nt" else "bin/python"
    )

    try:
        if not python.is_file():
            print(
                "SAVEMit is preparing its local plugin environment. "
                "This is a one-time setup.",
                file=sys.stderr,
            )
            run([sys.executable, "-m", "venv", str(environment_root)])
            run([
                str(python),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-input",
                str(repository_root),
            ])
    except subprocess.CalledProcessError as error:
        print(f"SAVEMit setup failed with exit code {error.returncode}.", file=sys.stderr)
        return error.returncode

    os.environ["PYTHONUNBUFFERED"] = "1"
    os.execv(str(python), [str(python), "-m", "app.mcp.server"])


if __name__ == "__main__":
    raise SystemExit(main())
