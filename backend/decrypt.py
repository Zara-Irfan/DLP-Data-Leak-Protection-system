# ============================================================
# DLP DECRYPT UTILITY
# Run from project root:  python backend/decrypt.py <file.enc>
# ============================================================

import os
import sys

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BACKEND_DIR)
os.chdir(PROJECT_DIR)
sys.path.insert(0, BACKEND_DIR)

from cryptography.fernet import Fernet, InvalidToken

KEY_FILE = "dlp.key"


def decrypt_file(path):
    if not os.path.exists(KEY_FILE):
        print(f"[ERROR] Key file '{KEY_FILE}' not found.")
        sys.exit(1)

    with open(KEY_FILE, "rb") as f:
        key = f.read()

    fernet = Fernet(key)

    if not os.path.isfile(path):
        print(f"[ERROR] File not found: {path}")
        sys.exit(1)

    try:
        with open(path, "rb") as fh:
            data = fh.read()
        decrypted = fernet.decrypt(data)
    except InvalidToken:
        print("[ERROR] Decryption failed: wrong key or corrupted file.")
        sys.exit(1)

    out_path = path[:-4] if path.endswith(".enc") else path + ".dec"
    with open(out_path, "wb") as fh:
        fh.write(decrypted)

    print(f"[OK] Decrypted: {path} -> {out_path}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python backend/decrypt.py <file.enc> [file2.enc ...]")
        sys.exit(1)

    for arg in sys.argv[1:]:
        decrypt_file(arg)
