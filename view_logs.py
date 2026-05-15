# This file has moved to backend/view_logs.py
# Usage: python backend/view_logs.py [--action BLOCK] [--limit 50]

import subprocess, sys, os

if __name__ == "__main__":
    script = os.path.join(os.path.dirname(__file__), "backend", "view_logs.py")
    subprocess.run([sys.executable, script] + sys.argv[1:])
