import json
from datetime import datetime

import boto3

from core.utils import *

BUCKET_NAME = 'your-bucket-name'  # Thay bằng tên bucket S3 của bạn


def receiver_cloud():
    # Tạo cặp khóa RSA
    private_key, public_key = generate_rsa_keys()
    save_keys(private_key, public_key, 'receiver_private.pem', 'receiver_public.pem')

    # Kết nối AWS S3
    s3 = boto3.client('s3')

    # Tải public key của sender
    s3.download_file(BUCKET_NAME, 'sender_public.pem', 'sender_public.pem')

    # Tải metadata
    metadata_obj = s3.get_object(Bucket=BUCKET_NAME, Key='email_metadata.json')
    packet = json.loads(metadata_obj['Body'].read().decode())
    iv = base64.b64decode(packet['iv'])
    hash_value = base64.b64decode(packet['hash'])
    signature = base64.b64decode(packet['sig'])
    expiration = packet['exp']
    encrypted_session_key = base64.b64decode(packet['encrypted_session_key'])

    # Tải file mã hóa
    cipher_obj = s3.get_object(Bucket=BUCKET_NAME, Key='email_cipher.txt')
    ciphertext = cipher_obj['Body'].read()

    # Kiểm tra thời hạn
    current_time = datetime.utcnow().isoformat() + 'Z'
    if current_time > expiration:
        raise Exception("NACK: Timeout")

    # Kiểm tra chữ ký
    metadata = f"email.txt|{expiration}".encode()
    if not verify_signature(metadata, signature, load_public_key('sender_public.pem')):
        raise Exception("NACK: Invalid signature")

    # Kiểm tra hash
    hash_input = iv + ciphertext + expiration.encode()
    if calculate_hash(hash_input) != hash_value:
        raise Exception("NACK: Integrity check failed")

    # Giải mã
    session_key = decrypt_session_key(encrypted_session_key, private_key)
    decrypted_data = aes_decrypt(iv, ciphertext, session_key)

    # Lưu file
    with open('received_email.txt', 'wb') as f:
        f.write(decrypted_data)

    return "ACK: File received and decrypted"
