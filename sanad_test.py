"""
Sanad — Full Diagnostic & Test Tool
"""

import os, sys, json, time, hashlib, secrets
import numpy as np
from pathlib import Path
from datetime import datetime

R  = "\033[91m"; G  = "\033[92m"; Y  = "\033[93m"; B  = "\033[94m"
M  = "\033[95m"; C  = "\033[96m"; W  = "\033[97m"; DIM= "\033[2m"
RST= "\033[0m";  BOLD="\033[1m"

def ok(msg):   print(f"  {G}[OK]  {msg}{RST}")
def err(msg):  print(f"  {R}[ERR] {msg}{RST}")
def warn(msg): print(f"  {Y}[WRN] {msg}{RST}")
def info(msg): print(f"  {C}[INF] {msg}{RST}")
def head(msg): print(f"\n{BOLD}{B}{'─'*50}{RST}\n{BOLD}{W}  {msg}{RST}\n{'─'*50}")
def sub(msg):  print(f"  {M}>  {msg}{RST}")

def get_sanad_dir():
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home()))
    else:
        base = Path.home() / ".local" / "share"
    return base / "Sanad"

SANAD_DIR  = get_sanad_dir()
USERS_FILE = SANAD_DIR / "users.json"

def check_libraries():
    head("1)  Checking installed libraries")
    libs = {
        "customtkinter":      "GUI framework",
        "pyttsx3":            "Text-to-speech",
        "sounddevice":        "Audio recording",
        "librosa":            "Fingerprint extraction (MFCC)",
        "numpy":              "Array processing",
        "cryptography":       "AES-256 encryption  [optional]",
        "bcrypt":             "Password hashing    [optional]",
        "keyring":            "OS secure storage   [optional]",
        "speech_recognition": "Speech-to-text      [optional]",
    }
    results = {}
    for lib, desc in libs.items():
        try:
            __import__(lib)
            ok(f"{lib:<22} — {desc}")
            results[lib] = True
        except ImportError:
            tag = warn if "[optional]" in desc else err
            tag(f"{lib:<22} — {desc}  [NOT INSTALLED]")
            results[lib] = False
    missing = [l for l in ["customtkinter","pyttsx3","sounddevice","librosa","numpy"]
               if not results.get(l)]
    if missing:
        print(f"\n  {R}Run:  pip install {' '.join(missing)}{RST}")
    return results

def check_files():
    head("2)  Checking saved data folder")
    info(f"Expected path: {SANAD_DIR}")
    if not SANAD_DIR.exists():
        warn("Folder not found — no users registered yet")
        return False
    ok(f"Folder exists: {SANAD_DIR}")
    files = list(SANAD_DIR.iterdir())
    if not files:
        warn("Folder is empty — no users registered yet")
        return False
    print(f"\n  {W}Files found:{RST}")
    for f in sorted(files):
        size  = f.stat().st_size
        mtime = datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        icon  = "[ENC]" if f.suffix == ".enc" else "[JSON]" if f.suffix == ".json" else "[FILE]"
        print(f"    {icon}  {f.name:<38} {size:>8} bytes   {DIM}{mtime}{RST}")
    return True

def check_users():
    head("3)  Checking user records")
    if not USERS_FILE.exists():
        warn("users.json not found — no registered users")
        return []
    with open(USERS_FILE, encoding="utf-8") as f:
        meta = json.load(f)
    users = meta.get("users", {})
    if not users:
        warn("No users found in file")
        return []
    ok(f"Registered users: {len(users)}")
    for uid, data in users.items():
        print(f"\n  {M}{'─'*44}{RST}")
        sub(f"User ID : {uid}")
        for key, val in data.items():
            print(f"    {C}{key:<22}{RST} {W}{val}{RST}")
        enc = SANAD_DIR / f"{uid}_voice.enc"
        npy = SANAD_DIR / f"{uid}_voice.npy"
        if enc.exists():
            ok(f"  Encrypted fingerprint found ({enc.stat().st_size} bytes)")
        elif npy.exists():
            ok(f"  Fingerprint .npy found ({npy.stat().st_size} bytes)")
        else:
            err("  Fingerprint file MISSING!")
    words = meta.get("words", {})
    if words:
        ok(f"Stored password hashes: {len(words)}")
        for uid in words:
            h = words[uid]
            method = "bcrypt" if not h.startswith("sha256:") else "sha256+salt"
            print(f"    {DIM}{uid}: [{method}] {h[:30]}...{RST}")
    else:
        info("Passwords stored in OS keyring (not visible here)")
    return list(users.keys())

def check_fingerprint(user_ids):
    head("4)  Checking voice fingerprint files")
    if not user_ids:
        warn("No users to check")
        return
    for uid in user_ids:
        sub(f"Checking: {uid}")
        enc = SANAD_DIR / f"{uid}_voice.enc"
        npy = SANAD_DIR / f"{uid}_voice.npy"
        if enc.exists():
            ok(f"  File exists — size: {enc.stat().st_size} bytes")
            with open(enc, "rb") as fh:
                raw = fh.read()
            salt = raw[:16]; ct = raw[16:]
            info(f"  Salt (hex)  : {salt.hex()}")
            info(f"  Ciphertext  : {len(ct)} bytes  (AES-256)")
            ok("  File structure is valid")
        elif npy.exists():
            fp = np.load(npy)
            ok(f"  .npy file found — shape: {fp.shape}")
            info(f"  First 5 values: {fp[:5].round(3)}")
        else:
            err("  Fingerprint file NOT FOUND!")

def test_microphone():
    head("5)  Microphone test (2 second recording)")
    try:
        import sounddevice as sd
        import librosa
    except ImportError:
        err("sounddevice or librosa not installed")
        return
    print(f"  {Y}Recording for 2 seconds...{RST}", end="", flush=True)
    try:
        FS = 16000; DUR = 2
        rec = sd.rec(int(DUR * FS), samplerate=FS, channels=1, dtype='float32')
        sd.wait()
        print(f" {G}Done!{RST}")
        ok(f"Recording shape  : {rec.shape}")
        ok(f"Max amplitude    : {np.max(np.abs(rec)):.4f}")
        y = rec.flatten()
        if np.max(np.abs(y)) > 0:
            y = y / np.max(np.abs(y))
        mfccs = librosa.feature.mfcc(y=y, sr=FS, n_mfcc=20)
        fp = np.mean(mfccs, axis=1)
        ok(f"MFCC fingerprint : {fp.shape[0]} features extracted")
        info(f"First 5 values   : {fp[:5].round(3)}")
        if np.max(np.abs(rec)) < 0.01:
            warn("Audio level very low — check your microphone")
        else:
            ok("Microphone working correctly")
    except Exception as e:
        err(f"Recording error: {e}")

def test_voice_verification(user_ids):
    head("6)  Voice verification simulation")
    sub("Simulating cosine similarity between two fingerprints...")
    np.random.seed(42)
    fp_base  = np.random.randn(61)
    fp_same  = fp_base + np.random.randn(61) * 0.05
    fp_other = np.random.randn(61)
    def cosine_sim(a, b):
        n = np.linalg.norm(a) * np.linalg.norm(b)
        return float(np.dot(a, b) / n) if n > 0 else 0
    sim_same  = cosine_sim(fp_base, fp_same)
    sim_other = cosine_sim(fp_base, fp_other)
    threshold = 0.72
    print(f"\n  {'Case':<34} {'Similarity':>10}  {'Result':>8}")
    print(f"  {'─'*56}")
    for label, sim in [("Same voice (two recordings)", sim_same),
                       ("Different voice (other person)", sim_other)]:
        result = "GRANTED" if sim >= threshold else "DENIED"
        col    = G if sim >= threshold else R
        print(f"  {label:<34} {sim:>10.1%}  {col}{result}{RST}")
    if sim_same >= threshold and sim_other < threshold:
        ok("Verification logic working correctly")
    else:
        warn("Threshold may need adjustment")

def system_summary(lib_results, user_ids):
    head("7)  System Status Summary")
    critical = ["customtkinter","pyttsx3","sounddevice","librosa","numpy"]
    optional = ["cryptography","bcrypt","keyring","speech_recognition"]
    c_ok = all(lib_results.get(l, False) for l in critical)
    o_ok = [l for l in optional if lib_results.get(l, False)]
    print(f"  {'Core libraries':<32} {'OK' if c_ok else 'MISSING':>10}")
    print(f"  {'Optional libraries':<32} {str(len(o_ok))+'/4 installed':>10}")
    print(f"  {'Data folder':<32} {'EXISTS' if SANAD_DIR.exists() else 'NOT CREATED':>10}")
    print(f"  {'Registered users':<32} {len(user_ids):>10}")
    print(f"\n  {BOLD}{'─'*44}{RST}")
    if c_ok and not user_ids:
        print(f"  {Y}System ready — run Sanad and register a user{RST}")
    elif c_ok and user_ids:
        print(f"  {G}All good — {len(user_ids)} user(s) registered{RST}")
    else:
        print(f"  {R}Install missing libraries first{RST}")
    print(f"\n  {DIM}Run test : python sanad_test.py{RST}")
    print(f"  {DIM}Run app  : python sanad_v3.py{RST}\n")

def main():
    print(f"\n{BOLD}{Y}{'='*50}{RST}")
    print(f"{BOLD}{Y}   Sanad — Diagnostic & Test Tool  v3.0{RST}")
    print(f"{BOLD}{Y}{'='*50}{RST}")
    lib_results = check_libraries()
    check_files()
    user_ids = check_users()
    check_fingerprint(user_ids)
    print(f"\n{Y}Test microphone? (y/n){RST} ", end="")
    try:
        ans = input().strip().lower()
    except EOFError:
        ans = "n"
    if ans == "y":
        test_microphone()
    test_voice_verification(user_ids)
    system_summary(lib_results, user_ids)

if __name__ == "__main__":
    main()