import base64
import io
import json
import logging
import os
from datetime import datetime

from cryptography.hazmat.primitives import serialization, constant_time
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload

from core.utils import load_public_key, verify_signature, aes_decrypt, calculate_hash, decrypt_session_key

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DATA_DIR = r"C:\Users\Admin\PycharmProjects\secure_file_transferr\data"
os.makedirs(DATA_DIR, exist_ok=True)

SCOPES = ['https://www.googleapis.com/auth/drive']
SERVICE_ACCOUNT_FILE = 'transferfile-462716-13da1f11d2f3.json'


def receive_cloud(file_id: str, receiver_email: str, sender_email: str = None):
    try:
        creds = service_account.Credentials.from_service_account_file(SERVICE_ACCOUNT_FILE, scopes=SCOPES)
        drive_service = build('drive', 'v3', credentials=creds, cache_discovery=False)

        # Lấy thông tin file để tạo cloud_link
        file_metadata = drive_service.files().get(fileId=file_id, fields='webViewLink').execute()
        cloud_link = file_metadata.get('webViewLink', None)
        if not cloud_link:
            logger.warning(f"Không thể tạo liên kết Drive cho file_id: {file_id}")
            cloud_link = None

        request = drive_service.files().get_media(fileId=file_id)
        file_stream = io.BytesIO()
        downloader = MediaIoBaseDownload(file_stream, request)
        done = False
        while done is False:
            status, done = downloader.next_chunk()
        file_stream.seek(0)
        packet_data = file_stream.read().decode('utf-8')
        logger.info(f"Raw packet data: {packet_data}")
        packet = json.loads(packet_data)

        iv = base64.b64decode(packet['iv'])
        ciphertext = base64.b64decode(packet['cipher'])
        received_hash = base64.b64decode(packet['hash'])
        signature = base64.b64decode(packet['sig'])
        exp = packet['exp']
        encrypted_session_key = base64.b64decode(packet['encrypted_session_key'])
        metadata = packet.get('metadata', f"email.txt|{exp}").encode()

        # Kiểm tra sender_email từ packet nếu được cung cấp
        packet_sender_email = packet.get('sender_email')
        if sender_email and packet_sender_email and sender_email != packet_sender_email:
            logger.error(f"Email người gửi không khớp: Provided {sender_email}, Packet {packet_sender_email}")
            return {"status": "NACK", "message": "Sender email mismatch"}
        elif not packet_sender_email:
            logger.error(
                f"Không tìm thấy email người gửi trong packet. Packet content: {json.dumps(packet, ensure_ascii=False)}")
            return {"status": "NACK", "message": "Sender email not found"}

        current_time = datetime.utcnow().isoformat() + 'Z'
        if current_time > exp:
            logger.error("File đã hết hạn!")
            return {"status": "NACK", "message": "Timeout"}

        hash_data = iv + ciphertext + exp.encode()
        calculated_hash = calculate_hash(hash_data)
        if not constant_time.bytes_eq(calculated_hash, received_hash):
            logger.error(f"Hash không khớp! Calculated: {calculated_hash.hex()}, Received: {received_hash.hex()}")
            return {"status": "NACK", "message": "Invalid hash"}

        sender_public_key_path = os.path.join(DATA_DIR, f"public_{packet_sender_email}.pem")
        if not os.path.exists(sender_public_key_path):
            logger.error(
                f"Khóa công khai của người gửi {packet_sender_email} không tồn tại tại {sender_public_key_path}")
            return {"status": "NACK", "message": f"Public key for {packet_sender_email} not found"}

        sender_public_key = load_public_key(sender_public_key_path)
        if not verify_signature(metadata, signature, sender_public_key):
            logger.error(f"Chữ ký không hợp lệ! Metadata: {metadata.decode()}, Signature: {signature.hex()}")
            return {"status": "NACK", "message": "Invalid signature"}

        private_key_path = os.path.join(DATA_DIR, f"private_{receiver_email}.pem")
        if not os.path.exists(private_key_path):
            logger.error(f"Khóa riêng tư của {receiver_email} không tồn tại")
            return {"status": "NACK", "message": f"Private key for {receiver_email} not found"}

        private_key = serialization.load_pem_private_key(
            open(private_key_path, 'rb').read(),
            password=None
        )
        session_key = decrypt_session_key(encrypted_session_key, private_key)

        try:
            plaintext = aes_decrypt(iv, ciphertext, session_key)
        except Exception as e:
            logger.error(f"Giải mã AES thất bại: {e}")
            return {"status": "NACK", "message": f"Decryption failed: {str(e)}"}

        filename = os.path.basename(metadata.decode().split('|')[0])
        output_path = os.path.join(DATA_DIR, f"received_{receiver_email.replace('@', '_')}_{filename}")
        try:
            with open(output_path, 'wb') as f:
                f.write(plaintext)
            logger.info(f"File giải mã lưu tại: {output_path}")
            return {
                "status": "ACK",
                "filename": filename,
                "decrypted_data": plaintext,
                "sender_email": packet_sender_email,
                "cloud_link": cloud_link,  # Thêm liên kết Drive
                "file_id": file_id  # Thêm file_id để tham chiếu
            }
        except Exception as e:
            logger.error(f"Lỗi lưu file: {e}")
            return {"status": "NACK", "message": f"Save failed: {str(e)}"}

    except Exception as e:
        logger.error(f"Lỗi nhận file từ Google Drive: {e}")
        return {"status": "NACK", "message": f"Error: {str(e)}"}
