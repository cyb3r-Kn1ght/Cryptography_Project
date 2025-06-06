from flask import Flask, render_template, send_from_directory, request, jsonify, redirect, url_for
import os
from sqlalchemy import create_engine, text
from dotenv import load_dotenv
from auth_utils import hash_password, verify_password

load_dotenv()

app = Flask(__name__)

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
                    SELECT password_hash FROM users WHERE username = :username
                """), {"username": username}).fetchone()

                if result and verify_password(result[0], password):
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
        password_hash = hash_password(password)

        try:
            with engine.begin() as conn:
                conn.execute(text("""
                    INSERT INTO users (username, email, password_hash)
                    VALUES (:username, :email, :password_hash)
                """), {
                    "username": username,
                    "email": email,
                    "password_hash": password_hash
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
    password_hash = hash_password(password)

    try:
        with engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO users (username, email, password_hash)
                VALUES (:username, :email, :password_hash)
            """), {
                "username": username,
                "email": email,
                "password_hash": password_hash
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
                SELECT password_hash FROM users WHERE username = :username
            """), {"username": username}).fetchone()

            if result and verify_password(result[0], password):
                return jsonify({"status": "success"})
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
    music_dir = os.path.join(app.root_path, 'static', 'music')
    music_files = os.listdir(music_dir)
    return render_template("index.html", music_files=music_files)

if __name__ == '__main__':
    app.run(debug=True)
