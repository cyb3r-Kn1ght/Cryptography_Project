from flask import Flask, render_template, send_from_directory, request, jsonify, redirect, url_for, session
import os
from sqlalchemy import create_engine, text
from dotenv import load_dotenv
from auth_utils import hash_password, verify_password
from crypto_utils import (
    generate_ecdhe_keypair,
    serialize_public_key,
    sign_ecdhe_pubkey,
    compute_shared_secret,
    get_ecdsa_public_key_bytes
)

load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Kết nối DB
engine = create_engine(os.getenv("DB_URL"))

# Trang mặc định: login
@app.route('/')
def root():
    return redirect(url_for('login_page'))

# Trang login (GET + POST)
@app.route("/login_page", methods=["GET", "POST"])
def login_page():
    if request.method == "GET":
        return render_template("login.html")
    else:
        username = request.form["username"]
        password = request.form["password"]

        try:
            with engine.connect() as conn:
                result = conn.execute(text("""
                    SELECT password_hash, role FROM users WHERE username = :username
                """), {"username": username}).fetchone()

                if result and verify_password(result[0], password):
                    session["username"] = username
                    session["role"] = result[1]
                    return redirect(url_for('index'))
                else:
                    return "Invalid credentials", 401
        except Exception as e:
            return f"Error: {e}", 500

# Trang register (GET + POST)
@app.route("/register_page", methods=["GET", "POST"])
def register_page():
    if request.method == "GET":
        return render_template("register.html")
    else:
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        role = request.form.get("role", "user")  # user hoặc artist
        password_hash = hash_password(password)

        try:
            with engine.begin() as conn:
                conn.execute(text("""
                    INSERT INTO users (username, email, password_hash, role)
                    VALUES (:username, :email, :password_hash, :role)
                """), {
                    "username": username,
                    "email": email,
                    "password_hash": password_hash,
                    "role": role
                })
            return redirect(url_for('login_page'))
        except Exception as e:
            return f"Error: {e}", 400

# Đăng ký API
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data["username"]
    email = data["email"]
    password = data["password"]
    role = data.get("role", "user")
    password_hash = hash_password(password)

    try:
        with engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO users (username, email, password_hash, role)
                VALUES (:username, :email, :password_hash, :role)
            """), {
                "username": username,
                "email": email,
                "password_hash": password_hash,
                "role": role
            })
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

# Đăng nhập API
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data["username"]
    password = data["password"]

    try:
        with engine.connect() as conn:
            result = conn.execute(text("""
                SELECT password_hash, role FROM users WHERE username = :username
            """), {"username": username}).fetchone()

            if result and verify_password(result[0], password):
                return jsonify({"status": "success", "role": result[1]})
            else:
                return jsonify({"status": "error", "message": "Invalid credentials"}), 401
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# Trả file nhạc từ static (tạm thời)
@app.route('/music/<filename>')
def play_music(filename):
    return send_from_directory("static/music", filename)

# Trang index để liệt kê nhạc (sau khi đăng nhập)
@app.route('/music_list')
def index():
    if "username" not in session:
        return redirect(url_for("login_page"))
    music_dir = os.path.join(app.root_path, 'static', 'music')
    music_files = os.listdir(music_dir)
    return render_template("index.html", music_files=music_files, role=session.get("role"))

# Upload nhạc (chỉ nghệ sĩ mới truy cập được)
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "username" not in session or session.get("role") != "artist":
        return "Unauthorized", 403

    if request.method == "GET":
        return render_template("upload.html")
    else:
        file = request.files["file"]
        save_path = os.path.join("static", "music", file.filename)
        file.save(save_path)
        return "Upload successful"

# Trao đổi khóa
session_keys = {}

@app.route("/key-exchange", methods=["GET"])
def key_exchange():
    server_priv, server_pub = generate_ecdhe_keypair()
    pub_bytes = serialize_public_key(server_pub)
    signature = sign_ecdhe_pubkey(pub_bytes)
    ecdsa_pub_bytes = get_ecdsa_public_key_bytes()

    session_keys["server_priv_ecdhe"] = server_priv

    return jsonify({
        "server_pubkey_ecdhe": pub_bytes.hex(),
        "signature": signature.hex(),
        "server_pubkey_ecdsa": ecdsa_pub_bytes.hex()
    })

@app.route("/submit-client-key", methods=["POST"])
def submit_client_key():
    data = request.json
    client_pub_hex = data["client_pubkey_ecdhe"]
    client_pub_bytes = bytes.fromhex(client_pub_hex)

    server_priv = session_keys.get("server_priv_ecdhe")
    if not server_priv:
        return jsonify({"status": "error", "message": "Session expired"}), 400

    shared_secret = compute_shared_secret(server_priv, client_pub_bytes)
    session_keys["shared_secret"] = shared_secret

    return jsonify({"status": "ok"})

if __name__ == '__main__':
    app.run(debug=True)
