import base64
import json
import os
from datetime import datetime, timedelta

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseUpload

from core.utils import generate_rsa_keys, save_keys, load_public_key, encrypt_session_key, aes_encrypt, sign_data, \
    calculate_hash

SCOPES = ['https://www.googleapis.com/auth/drive']
SERVICE_ACCOUNT_FILE = 'transferfile-462716-13da1f11d2f3.json'
FOLDER_ID = '1p5nJQXUNoo4XgDZtaZWSdmCO52smLRi4'
DATA_DIR = r"C:\Users\Admin\PycharmProjects\secure_file_transferr\data"

# Khởi tạo Google Drive API
creds = service_account.Credentials.from_service_account_file(SERVICE_ACCOUNT_FILE, scopes=SCOPES)
drive_service = build('drive', 'v3', credentials=creds, cache_discovery=False)


def send_cloud(file_path: str, receiver_email: str, sender_email: str):
    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File {file_path} không tồn tại")

        # Tạo và lưu khóa RSA cho người gửi
        private_key, public_key = generate_rsa_keys()
        sender_private_key_path = os.path.join(DATA_DIR, f"private_{sender_email}.pem")
        sender_public_key_path = os.path.join(DATA_DIR, f"public_{sender_email}.pem")
        save_keys(private_key, public_key, sender_private_key_path, sender_public_key_path)
        print(f"Saved sender keys: {sender_public_key_path}")

        # Tải khóa công khai của người nhận
        receiver_public_key_path = os.path.join(DATA_DIR, f"public_{receiver_email}.pem")
        if not os.path.exists(receiver_public_key_path):
            print(f"Debug: Files in {DATA_DIR}: {os.listdir(DATA_DIR)}")
            raise FileNotFoundError(f"Khóa công khai của {receiver_email} không tồn tại tại {receiver_public_key_path}")
        receiver_public_key = load_public_key(receiver_public_key_path)

        # Tiếp tục mã hóa và upload
        session_key = os.urandom(32)
        encrypted_session_key = encrypt_session_key(session_key, receiver_public_key)

        with open(file_path, 'rb') as f:
            data = b""
            for chunk in iter(lambda: f.read(8192), b""):
                data += chunk
        iv, ciphertext = aes_encrypt(data, session_key)

        expiration = (datetime.utcnow() + timedelta(hours=24)).isoformat() + 'Z'
        hash_data = iv + ciphertext + expiration.encode()
        file_hash = calculate_hash(hash_data)

        # Ký số metadata với tên file, email người gửi, và thời gian
        sign_time = datetime.utcnow().isoformat()
        metadata = f"{os.path.basename(file_path)}|{sender_email}|{sign_time}".encode()
        signature = sign_data(metadata, private_key)

        # Tạo gói tin với metadata khớp với dữ liệu ký
        packet = {
            'iv': base64.b64encode(iv).decode('utf-8'),
            'cipher': base64.b64encode(ciphertext).decode('utf-8'),
            'hash': base64.b64encode(file_hash).decode('utf-8'),
            'sig': base64.b64encode(signature).decode('utf-8'),
            'exp': expiration,
            'encrypted_session_key': base64.b64encode(encrypted_session_key).decode('utf-8'),
            'metadata': f"{os.path.basename(file_path)}|{sender_email}|{sign_time}",
            'sender_email': sender_email
        }

        # Ghi và kiểm tra packet cục bộ
        packet_file_path = os.path.join(DATA_DIR, f"packet_{os.path.basename(file_path)}.json")
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(packet_file_path, 'w', encoding='utf-8') as f:
            json.dump(packet, f, ensure_ascii=False, indent=2)
        with open(packet_file_path, 'r', encoding='utf-8') as f:
            saved_packet = json.load(f)
            print(f"Verified local packet content: {json.dumps(saved_packet, ensure_ascii=False)}")
            if 'sender_email' not in saved_packet:
                raise ValueError("sender_email missing in local packet")

        # Upload lên Google Drive
        file_metadata = {
            'name': f"packet_{os.path.basename(file_path)}.json",
            'parents': [FOLDER_ID],
            'mimeType': 'application/json'
        }
        with open(packet_file_path, 'rb') as file_stream:
            file_stream.seek(0)
            media = MediaIoBaseUpload(file_stream, mimetype='application/json', resumable=True)
            file = drive_service.files().create(body=file_metadata, media_body=media,
                                                fields='id, webViewLink').execute()
            file_id = file.get('id')
            file_url = file.get('webViewLink', f"https://drive.google.com/file/d/{file_id}/view")

        permission = {'role': 'reader', 'type': 'user', 'emailAddress': receiver_email}
        drive_service.permissions().create(fileId=file_id, body=permission, sendNotificationEmail=True).execute()

        os.remove(packet_file_path)
        with open(os.path.join(DATA_DIR, 'upload_log.txt'), 'a') as log:
            log.write(f"{file_id}|{expiration}\n")

        print(f"Uploaded packet to Google Drive: {file_url} with ID: {file_id}")
        return file_id, file_url

    except HttpError as e:
        print(f"Lỗi Google Drive API: {e} - Status: {e.resp.status}")
        return None, None
    except Exception as e:
        print(f"Lỗi: {e}")
        return None, None


# Hàm xóa file hết hạn (chạy định kỳ)
def delete_expired_files():
    log_file = os.path.join(DATA_DIR, 'upload_log.txt')
    if not os.path.exists(log_file):
        return
    with open(log_file, 'r') as f:
        lines = f.readlines()
    with open(log_file, 'w') as f:
        for line in lines:
            file_id, exp = line.strip().split('|')
            if datetime.utcnow().isoformat() + 'Z' < exp:
                f.write(line)
            else:
                try:
                    drive_service.files().delete(fileId=file_id).execute()
                    print(f"Deleted file {file_id}")
                except HttpError as e:
                    print(f"Lỗi xóa file {file_id}: {e}")
