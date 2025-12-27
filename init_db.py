import sqlite3
import hashlib
import os

conn = sqlite3.connect("database.db")
c = conn.cursor()

c.execute("""
CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    filename TEXT,
    encrypted_key BLOB,
    iv BLOB,
    service_option TEXT,
    photo_size TEXT,
    note TEXT,
    payment_method TEXT,
    status INTEGER DEFAULT 0
)
""")

c.execute("""
CREATE TABLE IF NOT EXISTS admin (
    username TEXT PRIMARY KEY,
    password_hash TEXT,
    salt TEXT
)
""")

# Admin credentials
username = "admin"
password = "secure_bot13"
salt = os.urandom(16).hex()
password_hash = hashlib.sha256((password + salt).encode()).hexdigest()

c.execute("DELETE FROM admin")
c.execute(
    "INSERT INTO admin VALUES (?, ?, ?)",
    (username, password_hash, salt)
)

conn.commit()
conn.close()
print("Database initialized.")
