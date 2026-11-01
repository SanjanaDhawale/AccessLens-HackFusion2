"""Start AccessLens frontend, backend, and synthetic test API together.

Run from repository root: python start.py
Press Ctrl+C to stop all services.
"""
import os
import signal
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SERVICES = [
    ("ConnectedCar test API", [sys.executable, "-m", "uvicorn", "target.main:app", "--host", "127.0.0.1", "--port", "8001"]),
    ("AccessLens backend", [sys.executable, "-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", "8000"]),
    ("AccessLens frontend", [sys.executable, "-m", "http.server", "5500", "--bind", "127.0.0.1", "--directory", "web"]),
]

def main():
    children = []
    try:
        for name, command in SERVICES:
            print(f"Starting {name}...", flush=True)
            kwargs = {"cwd": str(ROOT)}
            if os.name == "nt":
                kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
            proc = subprocess.Popen(command, **kwargs)
            children.append((name, proc))
            time.sleep(0.5)
            if proc.poll() is not None:
                raise RuntimeError(f"{name} exited immediately (code {proc.returncode}). Check dependencies and port availability.")
        print("\nAccessLens is starting. URLs:", flush=True)
        print("  User portal: http://127.0.0.1:5500/user-portal.html")
        print("  Homepage:    http://127.0.0.1:5500/")
        print("  Admin:       http://127.0.0.1:5500/admin-live.html")
        print("  Backend:     http://127.0.0.1:8000/api/health")
        print("  Target API:  http://127.0.0.1:8001/docs")
        print("\nPress Ctrl+C to stop all services.\n", flush=True)
        time.sleep(1)
        webbrowser.open("http://127.0.0.1:5500/user-portal.html")
        while True:
            time.sleep(1)
            for name, proc in children:
                if proc.poll() is not None:
                    raise RuntimeError(f"{name} stopped unexpectedly (code {proc.returncode}).")
    except KeyboardInterrupt:
        print("\nStopping AccessLens...", flush=True)
    except Exception as exc:
        print(f"\nStartup error: {exc}", file=sys.stderr, flush=True)
        return 1
    finally:
        for _, proc in reversed(children):
            if proc.poll() is None:
                if os.name == "nt":
                    proc.send_signal(signal.CTRL_BREAK_EVENT)
                else:
                    proc.terminate()
        for _, proc in reversed(children):
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
