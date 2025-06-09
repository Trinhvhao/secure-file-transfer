import os
import shutil
import sys
import threading
import time
from datetime import datetime, timedelta
from typing import List, Optional

import jwt
from flask import Flask, render_template, request, redirect, url_for, make_response, jsonify
from flask_sqlalchemy import SQLAlchemy
from passlib.context import CryptContext
import logging

# Thêm đường dẫn của thư mục core vào sys.path
sys.path.append(os.path.join(os.path.dirname(__file__), "core"))

# Import các module từ core/local
from core.local.sender_local import sender_local
from core.local.receiver_local import receiver_local

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
instance_dir = os.path.join(BASE_DIR, 'instance')
os.makedirs(instance_dir, exist_ok=True)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(instance_dir, "secure_file_transferr.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
status_log = []

# Cấu hình mã hóa mật khẩu
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = "your-secret-key-secure-1234567890"  # Thay bằng os.urandom(32).hex() trong production

# Mô hình người dùng
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True, index=True)
    username = db.Column(db.String, unique=True, index=True)
    hashed_password = db.Column(db.String)
    email = db.Column(db.String, unique=True, index=True, nullable=True)

# Mô hình lịch sử giao dịch
class TransferLog(db.Model):
    __tablename__ = "transfer_logs"
    id = db.Column(db.Integer, primary_key=True, index=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    receiver_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    file_name = db.Column(db.String)
    timestamp = db.Column(db.DateTime)
    status = db.Column(db.String)
    subject = db.Column(db.String, nullable=True)
    message = db.Column(db.String, nullable=True)

# Hàm lấy người dùng hiện tại
def get_current_user(request) -> Optional[User]:
    token = request.cookies.get("Authorization")
    if not token:
        return None
    if token.startswith("Bearer "):
        token = token[7:]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username = payload.get("sub")
        if not username:
            return None
        return User.query.filter_by(username=username).first()
    except (jwt.exceptions.ExpiredSignatureError, jwt.exceptions.InvalidTokenError):
        return None

# Cấu hình dữ liệu
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)
print(f"Main DATA_DIR: {DATA_DIR}")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Khởi động receiver
def start_receiver():
    while True:
        try:
            logger.info("Starting receiver...")
            receiver_local()
        except Exception as e:
            logger.error(f"Receiver error: {str(e)}")
            time.sleep(2)

def on_startup():
    receiver_thread = threading.Thread(target=start_receiver, daemon=True)
    receiver_thread.start()
    status_log.append("Receiver started in background")

# Gọi on_startup khi ứng dụng khởi động
on_startup()

# Hiển thị form đăng ký
@app.route("/register", methods=["GET"])
def register_form():
    return render_template("login.html", is_register=True)

# Đăng ký
@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    password = request.form.get("password")
    email = request.form.get("email")
    db_user = User.query.filter_by(username=username).first()
    if db_user:
        return render_template("login.html", message="Username already registered", is_register=True)
    hashed_password = pwd_context.hash(password)
    new_user = User(username=username, hashed_password=hashed_password, email=email)
    db.session.add(new_user)
    db.session.commit()
    token = jwt.encode({"sub": username, "exp": datetime.utcnow() + timedelta(hours=1)}, SECRET_KEY, algorithm="HS256")
    response = make_response(redirect(url_for("get_index")))
    response.set_cookie("Authorization", value=f"Bearer {token}", httponly=False, secure=True)  # Tạm thời httponly=False để test
    return response

# Hiển thị form đăng nhập
@app.route("/login", methods=["GET"])
def login_form():
    return render_template("login.html", is_login=True)

# Đăng nhập
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    user = User.query.filter_by(username=username).first()
    if not user or not pwd_context.verify(password, user.hashed_password):
        return render_template("login.html", message="Invalid username or password", is_login=True)
    token = jwt.encode({"sub": username, "exp": datetime.utcnow() + timedelta(hours=1)}, SECRET_KEY, algorithm="HS256")
    response = make_response(redirect(url_for("get_index")))
    response.set_cookie("Authorization", value=f"Bearer {token}", httponly=False, secure=True)  # Tạm thời httponly=False
    return response

# Trang chủ
@app.route("/", methods=["GET"])
def get_index():
    user = get_current_user(request)
    if not user:
        return redirect(url_for("login_form"))
    other_users = User.query.filter(User.id != user.id).all()
    logs = TransferLog.query.filter((TransferLog.sender_id == user.id) | (TransferLog.receiver_id == user.id)).all()
    history = [
        {
            "sender": User.query.get(log.sender_id).username,
            "receiver": User.query.get(log.receiver_id).username,
            "file": log.file_name,
            "timestamp": log.timestamp.isoformat(),
            "status": log.status,
            "subject": log.subject,
            "message": log.message
        }
        for log in logs
    ]
    return render_template("index.html", status_log=status_log, username=user.username, users=[u.username for u in other_users], history=history)

@app.route('/get_sender_info', methods=['GET'])
def get_sender_info():
    user = get_current_user(request)
    if not user:
        return jsonify({"message": "Please login to get sender info", "redirect": "/login"}), 401
    other_users = User.query.filter(User.id != user.id).all()
    return jsonify({
        "email": user.email,
        "username": user.username,
        "users": [u.username for u in other_users]
    }), 200

@app.route("/transfer", methods=["POST"])
def transfer_file():
    user = get_current_user(request)
    if not user:
        return jsonify({"message": "Please login to transfer files", "redirect": "/login"}), 401
    global status_log
    mode = request.form.get("mode")
    action = request.form.get("action")
    receiver_username = request.form.get("receiver_username")
    files = request.files.getlist("files")
    sender_email = request.form.get("sender_email")
    sender_username = request.form.get("sender_username")
    subject = request.form.get("subject")
    message = request.form.get("message")
    status_log.append(f"Mode: {mode}, Action: {action}, Sender: {sender_username} ({sender_email}), Receiver: {receiver_username}")

    receiver = User.query.filter_by(username=receiver_username).first()
    if not receiver:
        status_log.append(f"Error: Receiver {receiver_username} not found")
        return jsonify({"status_log": status_log, "message": f"Error: Receiver {receiver_username} not found"}), 400

    try:
        if action == "send":
            if not files or not all(f.filename.endswith('.txt') for f in files):
                status_log.append("Error: Please select only .txt files")
                return jsonify({"status_log": status_log, "message": "Error: Please select only .txt files"}), 400
            for file in files:
                file_path = os.path.join(DATA_DIR, file.filename)
                logger.info(f"Saving uploaded file to: {file_path}")
                file.save(file_path)
                if not os.path.exists(file_path):
                    status_log.append(f"Error: Failed to save file at {file_path}")
                    continue
                status_log.append(f"Selected file: {file.filename}")
                if mode == "Local":
                    start_time = time.time()
                    while time.time() - start_time < 15:
                        try:
                            result = sender_local(file_path, receiver_username)
                            if result == "ACK":
                                status_log.append(f"File {file.filename} sent successfully by {sender_username} to {receiver_username}")
                                log = TransferLog(
                                    sender_id=user.id,
                                    receiver_id=receiver.id,
                                    file_name=file.filename,
                                    timestamp=datetime.now(),
                                    status="success",
                                    subject=subject,
                                    message=message
                                )
                                db.session.add(log)
                                db.session.commit()
                            break
                        except Exception as e:
                            logger.warning(f"Retry sender for {file.filename}: {e}")
                            time.sleep(2)
                    else:
                        raise Exception(f"Sender timed out for {file.filename}")
                else:
                    status_log.append("Cloud mode not implemented")
        elif action == "receive":
            status_log.append(f"Receive action triggered for {user.username}, receiver is running in background")
    except Exception as e:
        status_log.append(f"Error: {str(e)}")
        return jsonify({"status_log": status_log, "message": f"Error: {str(e)}"}), 500

    return jsonify({"status_log": status_log, "username": user.username, "users": [u.username for u in User.query.filter(User.id != user.id).all()]}), 200

@app.route("/get_received_files", methods=["POST"])
def get_received_files():
    user = get_current_user(request)
    if not user:
        return jsonify({"message": "Please login to receive files", "redirect": "/login"}), 401
    global status_log
    try:
        receiver_email = request.json.get("receiver_email")
        receiver_username = request.json.get("receiver_username")
        sender_username = request.json.get("sender_username")
        status_log.append(f"Fetching files for {receiver_username} from {sender_username}")

        received_files = []
        logs = TransferLog.query.filter_by(receiver_id=user.id).all()
        for log in logs:
            sender = User.query.get(log.sender_id)
            if sender and sender.username == sender_username:
                received_files.append({
                    "name": log.file_name,
                    "size": 1024,  # Thay bằng kích thước thực tế nếu có
                    "sent_at": log.timestamp.isoformat()
                })
        if not received_files:
            status_log.append(f"No files found for {receiver_username} from {sender_username}")
        return jsonify({"files": received_files}), 200
    except Exception as e:
        status_log.append(f"Error fetching files: {str(e)}")
        return jsonify({"message": f"Error: {str(e)}"}), 500

@app.route("/history", methods=["GET"])
def get_history():
    user = get_current_user(request)
    if not user:
        return jsonify({"message": "Please login to view history", "redirect": "/login"}), 401
    logs = TransferLog.query.filter((TransferLog.sender_id == user.id) | (TransferLog.receiver_id == user.id)).all()
    history = [
        {
            "sender": User.query.get(log.sender_id).username,
            "receiver": User.query.get(log.receiver_id).username,
            "file": log.file_name,
            "timestamp": log.timestamp.isoformat(),
            "status": log.status,
            "subject": log.subject,
            "message": log.message
        }
        for log in logs
    ]
    return jsonify({"status_log": status_log, "username": user.username, "users": [u.username for u in User.query.filter(User.id != user.id).all()], "history": history}), 200

@app.route("/logout", methods=["GET"])
def logout():
    response = make_response(redirect(url_for("login_form")))
    response.delete_cookie("Authorization", path="/")
    return response

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)