"""Initialize the persistent data mount, then run the app without root privileges."""

import os
from pathlib import Path
import sys


uid = int(os.environ.get("APP_UID", "10001"))
gid = int(os.environ.get("APP_GID", str(uid)))
data_dir = Path(os.environ.get("BAYORA_DATA_DIR", "/data"))

if os.geteuid() == 0:
    data_dir.mkdir(parents=True, exist_ok=True)
    os.chown(data_dir, uid, gid)
    os.setgid(gid)
    os.setuid(uid)

if len(sys.argv) < 2:
    raise SystemExit("usage: start.py <application.py>")

os.execv(sys.executable, [sys.executable, "-u", *sys.argv[1:]])
