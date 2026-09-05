"""
Convenience launcher — runs the API + serves the UI on http://127.0.0.1:8000
Usage:  python run.py
"""
import os
import sys
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.join(HERE, "backend")


def main():
    port = os.environ.get("PORT", "8000")
    print("=" * 54)
    print("  Sentinel OSINT  →  http://127.0.0.1:%s" % port)
    print("  First run prints a one-time admin password below.")
    print("=" * 54)
    os.chdir(BACKEND)
    cmd = [sys.executable, "-m", "uvicorn", "main:app",
           "--host", "127.0.0.1", "--port", str(port)]
    if "--reload" in sys.argv:
        cmd.append("--reload")
    subprocess.run(cmd)


if __name__ == "__main__":
    main()
