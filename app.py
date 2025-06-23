import logging
import os
import re
import sys
import threading
import time
from datetime import datetime, timedelta
from typing import Optional

import jwt
import schedule
from flask import Flask, render_template, request, redirect, url_for, make_response, jsonify, send_from_directory, Response
from flask_sqlalchemy import SQLAlchemy
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseUpload
from passlib.context import CryptContext

sys.path.append(os.path.join(os.path.dirname(__file__), "core"))

from core.local.send_local import send_local
from core.local.receive_local import receive_local
from core.cloud.send_cloud import send_cloud
from core.cloud.receive_cloud import receive_cloud
from core.utils import generate_rsa_keys, save_keys

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
instance_dir = os.path.join(BASE_DIR, 'instance')
os.makedirs(instance_dir, exist_ok=True)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(instance_dir, "secure_file_transferr.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
status_log = []

# Đường dẫn dữ liệu động
DATA_DIR = os.getenv('DATA_DIR', os.path.join(BASE_DIR, "data"))
os.makedirs(DATA_DIR, exist_ok=True)
print(f"Main DATA_DIR: {DATA_DIR}")

# Cấu hình logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(BASE_DIR, 'app.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Cấu hình mã hóa mật khẩu
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = os.getenv('SECRET_KEY', 'your_fixed_secret_key_32_chars_long')

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
    cloud_link = db.Column(db.String, nullable=True)
    file_id = db.Column(db.String, nullable=True)

def get_current_user(request) -> Optional[User]:
    token = request.cookies.get("Authorization")
    logger.info(f"Received token: {token}")
    if not token:
        logger.info("No Authorization cookie found")
        return None
    if token.startswith("Bearer "):
        token = token[7:]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username = payload.get("sub")
        if not username:
            logger.error("No username in JWT payload")
            return None
        user = User.query.filter_by(username=username).first()
        if not user:
            logger.error(f"User not found in DB: {username}")
        else:
            logger.info(f"User authenticated: {username}")
        return user
    except jwt.exceptions.ExpiredSignatureError as e:
        logger.error(f"JWT expired: {str(e)}")
        return None
    except jwt.exceptions.InvalidTokenError as e:
        logger.error(f"JWT invalid: {str(e)}")
        return None

# Cấu hình Google Drive
SCOPES = ['https://www.googleapis.com/auth/drive']
SERVICE_ACCOUNT_FILE = 'transferfile-462716-13da1f11d2f3.json'
FOLDER_ID = '1p5nJQXUNoo4XgDZtaZWSdmCO52smLRi4'
creds = service_account.Credentials.from_service_account_file(SERVICE_ACCOUNT_FILE, scopes=SCOPES)
drive_service = build('drive', 'v3', credentials=creds, cache_discovery=False)
file_info = {}

def upload_file(file_stream, file_name, receiver_email):
    file_metadata = {
        'name': file_name,
        'parents': [FOLDER_ID],
        'mimeType': 'application/octet-stream'
    }
    file_stream.seek(0)
    media = MediaIoBaseUpload(file_stream, mimetype='text/plain', resumable=True)
    try:
        file = drive_service.files().create(body=file_metadata, media_body=media, fields='id, webViewLink').execute()
        file_id = file.get('id')
        permission = {
            'role': 'reader',
            'type': 'user',
            'emailAddress': receiver_email
        }
        drive_service.permissions().create(fileId=file_id, body=permission, sendNotificationEmail=True).execute()
        file_url = file.get('webViewLink', f"https://drive.google.com/file/d/{file_id}/view")
        logger.info(f"Uploaded file {file_name} with ID: {file_id}, URL: {file_url}")
        return file_id, file_url
    except HttpError as e:
        logger.error(f"Upload failed: {e}, Content: {e.content}")
        raise

def cleanup_files():
    current_time = datetime.now()
    for file_id, timestamp in list(file_info.items()):
        if current_time > timestamp + timedelta(hours=24):
            try:
                drive_service.files().delete(fileId=file_id).execute()
                logger.info(f"Deleted file {file_id}")
                del file_info[file_id]
            except HttpError as e:
                logger.error(f"Error deleting file {file_id}: {e}")

schedule.every(1).hours.do(cleanup_files)

def run_scheduler():
    while True:
        schedule.run_pending()
        time.sleep(3600)

threading.Thread(target=run_scheduler, daemon=True).start()

def start_receiver():
    while True:
        try:
            logger.info("Starting receiver...")
            receive_local(os.getenv('RECEIVER_EMAIL', 'receiver@example.com'))
        except Exception as e:
            logger.error(f"Receiver error: {str(e)}")
            time.sleep(2)

def on_startup():
    receiver_thread = threading.Thread(target=start_receiver, daemon=True)
    receiver_thread.start()
    status_log.append("Receiver started in background")

on_startup()

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("login.html", is_register=True)
    username = request.form.get("username")
    password = request.form.get("password")
    email = request.form.get("email")
    logger.info(f"Register attempt: username={username}, email={email}")
    if email and not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
        logger.error("Invalid email format")
        return render_template("login.html", message="Invalid email format", is_register=True)
    db_user = User.query.filter_by(username=username).first() or (User.query.filter_by(email=email).first() if email else None)
    if db_user:
        logger.error("Username or email already registered")
        return render_template("login.html", message="Username or email already registered", is_register=True)
    hashed_password = pwd_context.hash(password)
    new_user = User(username=username, hashed_password=hashed_password, email=email)
    try:
        db.session.add(new_user)
        db.session.commit()
        logger.info(f"User registered: {username}")
    except Exception as e:
        logger.error(f"Database error during register: {str(e)}")
        db.session.rollback()
        return render_template("login.html", message="Database error", is_register=True)
    private_key, public_key = generate_rsa_keys()
    key_identifier = email or username
    save_keys(private_key, public_key, os.path.join(DATA_DIR, f"private_{key_identifier}.pem"), os.path.join(DATA_DIR, f"public_{key_identifier}.pem"))
    token = jwt.encode({"sub": username, "exp": datetime.utcnow() + timedelta(hours=1)}, SECRET_KEY, algorithm="HS256")
    response = make_response(redirect(url_for("get_index")))
    response.set_cookie("Authorization", value=f"Bearer {token}", httponly=False, secure=False)
    return response

@app.route('/handshake', methods=['POST'])
def handshake():
    user = get_current_user(request)
    if not user:
        return jsonify({"message": "Please login", "redirect": "/login"}), 401
    data = request.get_json()
    if data and data.get('message') == 'Hello!':
        return jsonify({'message': 'Ready!'}), 200
    return jsonify({'message': 'Invalid handshake'}), 400

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", is_login=True)
    username = request.form.get("username")
    password = request.form.get("password")
    logger.info(f"Login attempt: username={username}")
    user = User.query.filter_by(username=username).first()
    if not user:
        logger.error(f"User not found: {username}")
        return render_template("login.html", message="Invalid username or password", is_login=True)
    if not pwd_context.verify(password, user.hashed_password):
        logger.error(f"Invalid password for user: {username}")
        return render_template("login.html", message="Invalid username or password", is_login=True)
    token = jwt.encode({"sub": username, "exp": datetime.utcnow() + timedelta(minutes=10)}, SECRET_KEY, algorithm="HS256")
    response = make_response(redirect(url_for("get_index")))
    response.set_cookie("Authorization", value=f"Bearer {token}", httponly=False, secure=False, path="/", samesite="Lax")
    logger.info(f"Login successful: {username}")
    return response

@app.route("/", methods=["GET"])
def get_index():
    user = get_current_user(request)
    if not user:
        return redirect(url_for("login"))
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
            "message": log.message,
            "cloud_link": log.cloud_link,
            "file_id": log.file_id
        }
        for log in logs
    ]
    return render_template("index.html", status_log=status_log, username=user.username,
                           users=[u.username for u in other_users], history=history, email=user.email)

@app.route('/get_sender_info', methods=['GET'])
def get_sender_info():
    user = get_current_user(request)
    if not user:
        return jsonify({"message": "Please login to get sender info", "redirect": "/login"}), 401
    other_users = User.query.filter(User.id != user.id).all()
    return jsonify({
        "email": user.email,
        "username": user.username,
        "users": [{"username": u.username, "email": u.email} for u in other_users]
    }), 200

@app.route("/get_received_files", methods=["POST"])
def get_received_files():
    user = get_current_user(request)
    if not user:
        return jsonify({"message": "Please login to receive files", "redirect": "/login"}), 401
    try:
        receiver_email = request.json.get("receiver_email")
        sender_username = request.json.get("sender_username")
        status_log.append(f"Fetching files for {receiver_email} from {sender_username}")

        received_files = []
        for filename in os.listdir(DATA_DIR):
            if filename.startswith(f"received_{receiver_email.replace('@', '_')}_"):
                file_path = os.path.join(DATA_DIR, filename)
                log = TransferLog.query.filter_by(receiver_id=user.id, file_name=filename.replace(
                    f"received_{receiver_email.replace('@', '_')}_", "")).first()
                if log and User.query.get(log.sender_id).username == sender_username:
                    received_files.append({
                        "name": filename,
                        "size": os.path.getsize(file_path),
                        "sent_at": log.timestamp.isoformat() if log else datetime.now().isoformat(),
                        "download_url": url_for("download_file", filename=filename),
                        "source": "local" if not log.cloud_link else "cloud"
                    })
        if not received_files:
            status_log.append(f"No files found for {receiver_email} from {sender_username}")
        return jsonify({"files": received_files}), 200
    except Exception as e:
        status_log.append(f"Error fetching files: {str(e)}")
        return jsonify({"message": f"Error: {str(e)}"}), 500

@app.route("/download/<filename>", methods=["GET"])
def download_file(filename):
    user = get_current_user(request)
    if not user:
        return jsonify({"message": "Please login to download files", "redirect": "/login"}), 401
    file_path = os.path.join(DATA_DIR, filename)
    if os.path.exists(file_path) and filename.startswith(f"received_{user.email.replace('@', '_')}_"):
        response = send_from_directory(DATA_DIR, filename, as_attachment=True,
                                       download_name=filename.replace(f"received_{user.email.replace('@', '_')}_", ""))
        try:
            os.remove(file_path)
            status_log.append(f"File {filename} downloaded and removed")
        except Exception as e:
            status_log.append(f"Error removing file {filename}: {str(e)}")
        return response
    return jsonify({"message": "File not found or access denied"}), 404

@app.route("/download_decrypted", methods=["GET"])
def download_decrypted():
    user = get_current_user(request)
    if not user:
        return jsonify({"message": "Please login to download files", "redirect": "/login"}), 401

    filename = request.args.get("filename")
    email = request.args.get("email")
    if not filename or not email:
        return jsonify({"message": "Missing filename or email"}), 400

    file_path = os.path.join(DATA_DIR, f"received_{email.replace('@', '_')}_{filename}")
    if os.path.exists(file_path):
        response = send_from_directory(DATA_DIR, f"received_{email.replace('@', '_')}_{filename}", as_attachment=True,
                                       download_name=filename)
        try:
            os.remove(file_path)  # Xóa file sau khi tải
            status_log.append(f"File {filename} downloaded and removed")
        except Exception as e:
            status_log.append(f"Error removing file {filename}: {str(e)}")
        return response
    return jsonify({"message": "File not found or access denied"}), 404

@app.route("/preview_decrypted", methods=["GET"])
def preview_decrypted():
    user = get_current_user(request)
    if not user:
        return jsonify({"message": "Please login to preview files", "redirect": "/login"}), 401

    filename = request.args.get("filename")
    email = request.args.get("email")
    if not filename or not email:
        return jsonify({"message": "Missing filename or email"}), 400

    file_path = os.path.join(DATA_DIR, f"received_{email.replace('@', '_')}_{filename}")
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        return Response(content, mimetype='text/plain')
    return jsonify({"message": "File not found or access denied"}), 404

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
            "message": log.message,
            "cloud_link": log.cloud_link,
            "file_id": log.file_id
        }
        for log in logs
    ]
    return jsonify({"status_log": status_log, "username": user.username,
                    "users": [{"username": u.username, "email": u.email} for u in
                              User.query.filter(User.id != user.id).all()], "history": history}), 200

@app.route("/logout", methods=["GET"])
def logout():
    response = make_response(redirect(url_for("login")))
    response.delete_cookie("Authorization", path="/")
    return response

@app.route("/transfer", methods=["POST"])
def transfer_file():
    user = get_current_user(request)
    if not user:
        return jsonify({"message": "Please login to transfer files", "redirect": "/login"}), 401
    global status_log
    mode = request.form.get("mode")
    action = request.form.get("action")
    receiver_email = request.form.get("receiver_email")
    files = request.files.getlist("files")
    subject = request.form.get("subject")
    message = request.form.get("message")
    receiver_ip = request.form.get("receiver_ip") if mode == "Local" else None

    logger.info(f"Transfer request: mode={mode}, action={action}, receiver_email={receiver_email}, files={len(files)}")
    if not receiver_email or not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", receiver_email):
        status_log.append(f"Error: Invalid or missing receiver email {receiver_email}")
        logger.error(f"Invalid receiver email: {receiver_email}")
        return jsonify({"status_log": status_log, "message": "Error: Invalid or missing receiver email"}), 400

    receiver = User.query.filter_by(email=receiver_email).first()
    if not receiver:
        status_log.append(f"Error: Receiver with email {receiver_email} not found")
        logger.error(f"Receiver not found: {receiver_email}")
        return jsonify({"status_log": status_log, "message": f"Error: Receiver with email {receiver_email} not found"}), 400

    try:
        if action == "send":
            if not files or not all(f.filename.endswith('.txt') for f in files):
                status_log.append("Error: Please select only .txt files")
                logger.error("Invalid file types: Only .txt files allowed")
                return jsonify({"status_log": status_log, "message": "Error: Please select only .txt files"}), 400
            for file in files:
                file_name = file.filename
                status_log.append(f"Processing file: {file_name}")
                logger.info(f"Processing file: {file_name}")
                file_path = os.path.join(DATA_DIR, file_name)
                file.save(file_path)
                if not os.path.exists(file_path):
                    status_log.append(f"Error: Failed to save file at {file_path}")
                    logger.error(f"Failed to save file: {file_path}")
                    continue
                if mode == "Local":
                    if not receiver_ip or not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", receiver_ip):
                        status_log.append(f"Error: Invalid or missing receiver IP {receiver_ip}")
                        logger.error(f"Invalid receiver IP: {receiver_ip}")
                        return jsonify({"status_log": status_log, "message": "Error: Invalid or missing receiver IP"}), 400
                    result = send_local(file_path, receiver_email, receiver_ip)
                    if result == "ACK":
                        status_log.append(f"File {file_name} sent and decrypted successfully to {receiver_email}")
                        logger.info(f"File sent successfully: {file_name} to {receiver_email}")
                        log = TransferLog(
                            sender_id=user.id,
                            receiver_id=receiver.id,
                            file_name=file_name,
                            timestamp=datetime.now(),
                            status="success",
                            subject=subject,
                            message=message
                        )
                        db.session.add(log)
                        db.session.commit()
                elif mode == "Cloud":
                    try:
                        file_id, file_url = send_cloud(file_path, receiver_email, user.email)
                        if file_id:
                            file_info[file_id] = datetime.now()
                            status_log.append(f"File {file_name} uploaded to Google Drive with ID: {file_id}, URL: {file_url}")
                            logger.info(f"File uploaded to Google Drive: {file_name}, ID: {file_id}, URL: {file_url}")
                            log = TransferLog(
                                sender_id=user.id,
                                receiver_id=receiver.id,
                                file_name=file_name,
                                timestamp=datetime.now(),
                                status="success",
                                subject=subject,
                                message=message,
                                cloud_link=file_url,
                                file_id=file_id
                            )
                            db.session.add(log)
                            db.session.commit()
                        else:
                            status_log.append(f"Failed to upload {file_name} to Cloud")
                            logger.error(f"Failed to upload file: {file_name}")
                            raise Exception("Upload failed")
                    except Exception as e:
                        status_log.append(f"Error uploading to Cloud: {str(e)}")
                        logger.error(f"Cloud upload error: {str(e)}")
                        return jsonify({"status_log": status_log, "message": f"Error: {str(e)}"}), 500
                else:
                    status_log.append("Unsupported mode")
                    logger.error("Unsupported mode")
                    return jsonify({"status_log": status_log, "message": "Error: Unsupported mode"}), 400
                os.remove(file_path)
                status_log.append(f"File {file_name} processed and removed from local storage")
                logger.info(f"File {file_name} removed from local storage")
        elif action == "receive":
            status_log.append(f"Receive action triggered for {user.email}, receiver is running in background")
            logger.info(f"Receive action triggered for {user.email}")
    except Exception as e:
        status_log.append(f"Error: {str(e)}")
        logger.error(f"Transfer error: {str(e)}")
        return jsonify({"status_log": status_log, "message": f"Error: {str(e)}"}), 500

    logger.info(f"Transfer completed successfully for user: {user.username}, mode: {mode}")
    return jsonify({
        "status_log": status_log,
        "username": user.username,
        "users": [{"username": u.username, "email": u.email} for u in User.query.filter(User.id != user.id).all()],
        "message": "File encrypted, sent, and available for download by recipient" if action == "send" else "",
        "cloud_link": log.cloud_link if 'log' in locals() and log.cloud_link else None,
        "file_id": log.file_id if 'log' in locals() and log.file_id else None
    }), 200

@app.route("/receive_cloud", methods=["POST"])
def receive_cloud_route():
    user = get_current_user(request)
    if not user:
        return jsonify({"message": "Please login to receive files", "redirect": "/login"}), 401

    file_id = request.form.get("file_id")
    if not file_id:
        file_id = request.json.get("file_id") if request.is_json else None
        if not file_id:
            return jsonify({"success": False, "message": "Missing file ID", "status_log": status_log}), 400

    sender_email = request.form.get("sender_email") or request.json.get("sender_email") if request.is_json else ""
    try:
        result = receive_cloud(file_id, user.email, sender_email=sender_email)
        if result["status"] == "ACK":
            sender_email = result.get("sender_email", sender_email)
            status_log.append(f"File {result['filename']} received and decrypted successfully from Google Drive (ID: {file_id})")
            log = TransferLog.query.filter_by(file_id=file_id, receiver_id=user.id).first()
            if log:
                log.status = "received"
                db.session.commit()
                timestamp = log.timestamp.isoformat() + "Z" if log.timestamp else datetime.utcnow().isoformat() + "Z"
            else:
                timestamp = datetime.utcnow().isoformat() + "Z"
            return jsonify({
                "success": True,
                "filename": result["filename"],
                "sender_email": sender_email,
                "timestamp": timestamp,
                "file_id": file_id,
                "cloud_link": result["cloud_link"],
                "status_log": status_log
            }), 200
        else:
            status_log.append(f"Error receiving file: {result['message']}")
            return jsonify({"success": False, "message": result["message"], "status_log": status_log}), 500
    except Exception as e:
        status_log.append(f"Error receiving cloud file: {str(e)}")
        return jsonify({"success": False, "message": str(e), "status_log": status_log}), 500

if __name__ == "__main__":
    with app.app_context():
        try:
            db.create_all()
            logger.info("Database tables created successfully")
        except Exception as e:
            logger.error(f"Error creating database: {str(e)}")
    app.run(host="0.0.0.0", port=8000, debug=True)