"""
Sanad — Cleanup Tool
Deletes duplicate/old user accounts, keeps only the latest one.
"""

import os, json, shutil
from pathlib import Path
from datetime import datetime

R="\033[91m"; G="\033[92m"; Y="\033[93m"; C="\033[96m"; W="\033[97m"; RST="\033[0m"; BOLD="\033[1m"

def get_sanad_dir():
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home()))
    else:
        base = Path.home() / ".local" / "share"
    return base / "Sanad"

SANAD_DIR  = get_sanad_dir()
USERS_FILE = SANAD_DIR / "users.json"

def load_meta():
    if not USERS_FILE.exists():
        return {}
    with open(USERS_FILE, encoding="utf-8") as f:
        return json.load(f)

def save_meta(data):
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def list_users(meta):
    users = meta.get("users", {})
    if not users:
        print(f"{Y}No users found.{RST}")
        return
    print(f"\n{BOLD}{'#':<4} {'User ID':<22} {'Created At':<22} {'Method'}{RST}")
    print("─" * 65)
    for i, (uid, info) in enumerate(users.items(), 1):
        created = info.get("created_at", "unknown")
        method  = info.get("auth_method", "—")
        enc     = (SANAD_DIR / f"{uid}_voice.enc").exists()
        flag    = f"{G}[ENC]{RST}" if enc else f"{R}[MISSING]{RST}"
        print(f"{i:<4} {uid:<22} {created:<22} {flag}")

def delete_user(meta, uid):
    # Remove from JSON
    meta.get("users", {}).pop(uid, None)
    meta.get("words", {}).pop(uid, None)
    # Remove fingerprint files
    for ext in [".enc", ".npy"]:
        f = SANAD_DIR / f"{uid}_voice{ext}"
        if f.exists():
            f.unlink()
            print(f"  {R}Deleted:{RST} {f.name}")
    print(f"  {G}User {uid} removed.{RST}")

def main():
    print(f"\n{BOLD}{Y}{'='*50}{RST}")
    print(f"{BOLD}{Y}   Sanad — Cleanup Tool{RST}")
    print(f"{BOLD}{Y}{'='*50}{RST}")

    meta  = load_meta()
    users = meta.get("users", {})

    if not users:
        print(f"\n{Y}No users stored. Nothing to clean.{RST}\n")
        return

    print(f"\n{C}Found {len(users)} stored user(s):{RST}")
    list_users(meta)

    print(f"\n{BOLD}Options:{RST}")
    print(f"  {W}1{RST} — Delete ALL users (full reset)")
    print(f"  {W}2{RST} — Keep ONLY the latest user, delete the rest")
    print(f"  {W}3{RST} — Delete a specific user by number")
    print(f"  {W}4{RST} — Exit without changes")
    print(f"\nChoice: ", end="")

    choice = input().strip()

    if choice == "1":
        confirm = input(f"{R}Delete ALL {len(users)} users? (yes/no): {RST}").strip().lower()
        if confirm == "yes":
            for uid in list(users.keys()):
                delete_user(meta, uid)
            save_meta(meta)
            print(f"\n{G}Done — all users deleted.{RST}")
        else:
            print(f"{Y}Cancelled.{RST}")

    elif choice == "2":
        # Sort by created_at, keep the newest
        sorted_users = sorted(users.items(),
                              key=lambda x: x[1].get("created_at", ""),
                              reverse=True)
        keep_uid = sorted_users[0][0]
        to_delete = [uid for uid, _ in sorted_users[1:]]
        print(f"\n{G}Keeping: {keep_uid}{RST}")
        print(f"{R}Deleting {len(to_delete)} old user(s)...{RST}")
        for uid in to_delete:
            delete_user(meta, uid)
        save_meta(meta)
        print(f"\n{G}Done — kept the latest user only.{RST}")

    elif choice == "3":
        uids = list(users.keys())
        print(f"Enter user number (1-{len(uids)}): ", end="")
        try:
            n   = int(input().strip()) - 1
            uid = uids[n]
            confirm = input(f"{R}Delete user '{uid}'? (yes/no): {RST}").strip().lower()
            if confirm == "yes":
                delete_user(meta, uid)
                save_meta(meta)
                print(f"\n{G}Done.{RST}")
            else:
                print(f"{Y}Cancelled.{RST}")
        except (ValueError, IndexError):
            print(f"{R}Invalid number.{RST}")

    elif choice == "4":
        print(f"{Y}No changes made.{RST}")
    else:
        print(f"{R}Invalid choice.{RST}")

    # Show final state
    meta_after = load_meta()
    remaining  = len(meta_after.get("users", {}))
    print(f"\n{C}Users remaining: {remaining}{RST}\n")

if __name__ == "__main__":
    main()