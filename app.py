from flask import (
    Flask, request, jsonify, render_template,
    redirect, session, send_file
)
import sqlite3
import os
import hashlib

from crypto.aes import encrypt_file, decrypt_file
from crypto.rsa import generate_keys, encrypt_key, decrypt_key

app = Flask(__name__)
app.secret_key = "supersecretkey-demo"

UPLOAD_DIR = "uploads_encrypted"
DECRYPT_DIR = "decrypted_temp"

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(DECRYPT_DIR, exist_ok=True)

generate_keys()

# =========================
# USER SIDE
# =========================

@app.route("/", methods=["GET"])
def index():
    return render_template("upload.html")


@app.route("/upload", methods=["POST"])
def upload():
    username = request.form["username"]
    service_option = request.form["service"]
    note = request.form.get("note", "")
    payment = request.form["payment"]
    file = request.files["file"]
    photo_size = request.form.get("photo_size", None)


    data = file.read()
    encrypted_data, aes_key, iv = encrypt_file(data)
    encrypted_key = encrypt_key(aes_key)
    

    filename = file.filename + ".enc"
    path = os.path.join(UPLOAD_DIR, filename)

    with open(path, "wb") as f:
        f.write(encrypted_data)

    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("""
        INSERT INTO orders
        (username, filename, encrypted_key, iv, service_option, photo_size, note, payment_method)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        username, filename, encrypted_key, iv,
        service_option, photo_size, note, payment
    ))
    conn.commit()
    conn.close()

    return render_template("success.html")


# =========================
# ADMIN AUTH
# =========================

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "GET":
        return render_template("admin_login.html")

    username = request.form["username"]
    password = request.form["password"]

    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute(
        "SELECT password_hash, salt FROM admin WHERE username=?",
        (username,)
    )
    result = c.fetchone()
    conn.close()

    if not result:
        return "Login gagal"

    stored_hash, salt = result
    input_hash = hashlib.sha256((password + salt).encode()).hexdigest()

    if input_hash == stored_hash:
        session["admin"] = username
        return redirect("/admin/dashboard")

    return "Login gagal"


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    return redirect("/admin/login")


# =========================
# ADMIN DASHBOARD
# =========================

@app.route("/admin/dashboard")
def admin_dashboard():
    if "admin" not in session:
        return redirect("/admin/login")

    conn = sqlite3.connect("database.db")
    c = conn.cursor()

    c.execute("SELECT * FROM orders WHERE status=0")
    pending = c.fetchall()

    c.execute("SELECT * FROM orders WHERE status=1")
    downloaded = c.fetchall()

    conn.close()

    return render_template(
        "admin_dashboard.html",
        pending=pending,
        downloaded=downloaded
    )


# =========================
# DOWNLOAD & DECRYPT
# =========================

@app.route("/admin/download/<int:order_id>")
def download(order_id):
    if "admin" not in session:
        return redirect("/admin/login")

    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("""
        SELECT filename, encrypted_key, iv
        FROM orders WHERE id=?
    """, (order_id,))
    row = c.fetchone()
    conn.close()

    if not row:
        return "File tidak ditemukan"

    filename, encrypted_key, iv = row
    encrypted_path = os.path.join(UPLOAD_DIR, filename)

    with open(encrypted_path, "rb") as f:
        encrypted_data = f.read()

    aes_key = decrypt_key(encrypted_key)
    decrypted_data = decrypt_file(encrypted_data, aes_key, iv)

    output_filename = filename.replace(".enc", "")
    output_path = os.path.join(DECRYPT_DIR, output_filename)

    with open(output_path, "wb") as f:
        f.write(decrypted_data)

    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("UPDATE orders SET status=1 WHERE id=?", (order_id,))
    conn.commit()
    conn.close()

    return send_file(output_path, as_attachment=True)


# =========================
# MAIN
# =========================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

