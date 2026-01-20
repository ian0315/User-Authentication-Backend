import os
import sqlite3
import hashlib
import secrets
from getpass import getpass

DB_PATH = "data.db"


def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_bytes(16)

    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        200_000,
    )
    return f"{salt.hex()}:{dk.hex()}"


def verify_password(password, stored):
    try:
        salt_hex, hash_hex = stored.split(":", 1)
    except ValueError:
        return False

    salt = bytes.fromhex(salt_hex)
    candidate = hash_password(password, salt)
    return secrets.compare_digest(candidate, stored)


def connect_db():
    return sqlite3.connect(DB_PATH)


def init_db(reset=False):
    if reset and os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    with connect_db() as con:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL
            )
            """
        )


def create_user(username, password):
    pw_hash = hash_password(password)

    try:
        with connect_db() as con:
            con.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, pw_hash),
            )
        return True
    except sqlite3.IntegrityError:
        return False


def authenticate(username, password):
    with connect_db() as con:
        cur = con.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (username,),
        )
        row = cur.fetchone()

    if row is None:
        return False

    return verify_password(password, row[0])


def register():
    username = input("Enter your username: ").strip()
    password = getpass("Enter your password: ")

    if create_user(username, password):
        print("Successful register.")
    else:
        print("Username already exists.")


def login():
    username = input("Enter your username: ").strip()
    password = getpass("Enter your password: ")

    if authenticate(username, password):
        print("Successful login.")
    else:
        print("Unsuccessful login.")


def main():
    if os.path.exists(DB_PATH):
        while True:
            choice = input("Database already exists. Reset it? (yes/no): ").strip().lower()
            if choice in {"yes", "y"}:
                init_db(reset=True)
                break
            if choice in {"no", "n"}:
                init_db()
                break
            print("Not a valid choice.")
    else:
        init_db()

    while True:
        action = input("Type 'login', 'register', or '-1' to exit: ").strip().lower()

        if action == "login":
            login()
        elif action == "register":
            register()
        elif action == "-1":
            print("Exiting...")
            break
        else:
            print("Invalid input.")


if __name__ == "__main__":
    main()
