import os
import sqlite3
from flask_sqlalchemy import SQLAlchemy
from passlib.context import CryptContext

# Cấu hình tạm thời cho SQLAlchemy
db = SQLAlchemy()

# Cấu hình mã hóa mật khẩu
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

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

def initialize_database():
    # Lấy đường dẫn tuyệt đối tới thư mục instance của dự án
    base_dir = os.path.dirname(os.path.abspath(__file__))
    instance_dir = os.path.join(base_dir, 'instance')
    os.makedirs(instance_dir, exist_ok=True)  # Tạo thư mục instance nếu chưa tồn tại
    db_path = os.path.join(instance_dir, 'secure_file_transferr.db')

    # Xóa file database cũ nếu tồn tại
    if os.path.exists(db_path):
        os.remove(db_path)
        print(f"Deleted existing database: {db_path}")

    # Tạo kết nối và tạo bảng mới
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        # Tạo bảng users
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                hashed_password TEXT NOT NULL,
                email TEXT UNIQUE
            )
        ''')
        print("Created table 'users'")

        # Tạo bảng transfer_logs
        cursor.execute('''
            CREATE TABLE transfer_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER,
                receiver_id INTEGER,
                file_name TEXT,
                timestamp TEXT,
                status TEXT,
                subject TEXT,
                message TEXT,
                FOREIGN KEY (sender_id) REFERENCES users(id),
                FOREIGN KEY (receiver_id) REFERENCES users(id)
            )
        ''')
        print("Created table 'transfer_logs'")

        # Thêm dữ liệu mẫu
        cursor.execute("INSERT INTO users (username, hashed_password, email) VALUES (?, ?, ?)",
                       ("user1", pwd_context.hash("pass123"), "user1@example.com"))
        conn.commit()
        print("Added sample user: user1")

    except sqlite3.Error as e:
        print(f"Error creating database: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    initialize_database()
    print("Database initialization completed. You can now run the application.")