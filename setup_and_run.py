"""Windows-friendly Docker Compose bootstrap for CTI Sentinel X."""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main() -> int:
    docker = shutil.which("docker")
    if not docker:
        print("[ERROR] Docker Desktop is required. Install/start it, then retry.")
        return 1
    env_result = subprocess.run([sys.executable, "scripts/prepare_env.py"], cwd=ROOT)
    if env_result.returncode:
        return env_result.returncode
    info = subprocess.run([docker, "info"], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if info.returncode:
        print("[ERROR] Docker Desktop is installed but its engine is not ready.")
        return info.returncode
    command = [docker, "compose", "-f", "docker-compose.yml", "up", "-d", "--build"]
    print("[RUN]", " ".join(command))
    result = subprocess.run(command, cwd=ROOT)
    if result.returncode:
        return result.returncode
    print("[READY] Open http://localhost:5000")
    print("[API] FastAPI documentation: http://localhost:8000/docs")
    print("[MONGO] MongoDB is mapped to localhost:27018")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
