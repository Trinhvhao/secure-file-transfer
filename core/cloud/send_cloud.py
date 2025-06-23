import base64
import json
from datetime import datetime, timedelta

import boto3

from core.utils import *

BUCKET_NAME = 'your-bucket-name'  # Thay bằng tên bucket S3 của bạn


def sender_cloud(file_path='email.txt'):
    # Tạo cặp khóa RSA
    private_key, public_key = generate_rsa_keys()
    save_keys(private_key, public_key, 'sender_private.pem', 'sender_public.pem')

    # Đọc file
    with open(file_path, 'rb') as f:
        file_data = f.read()

    # Tạo session key
    session_key = os.urandom(32)

    # Mã hóa file
    iv, ciphertext = aes_encrypt(file_data, session_key)
    timestamp = datetime.utcnow().isoformat() + 'Z'
    expiration = (datetime.utcnow() + timedelta(hours=24)).isoformat() + 'Z'
    metadata = f"email.txt|{timestamp}".encode()
    signature = sign_data(metadata, private_key)
    encrypted_session_key = encrypt_session_key(session_key, load_public_key('receiver_public.pem'))
    hash_input = iv + ciphertext + expiration.encode()
    hash_value = calculate_hash(hash_input)

    # Tạo gói metadata
    packet = {
        "iv": base64.b64encode(iv).decode(),
        "hash": base64.b64encode(hash_value).decode(),
        "sig": base64.b64encode(signature).decode(),
        "exp": expiration,
        "encrypted_session_key": base64.b64encode(encrypted_session_key).decode()
    }

    # Kết nối AWS S3
    s3 = boto3.client('s3')

    # Tải file mã hóa
    s3.put_object(
        Bucket=BUCKET_NAME,
        Key='email_cipher.txt',
        Body=ciphertext
    )

    # Tải metadata
    s3.put_object(
        Bucket=BUCKET_NAME,
        Key='email_metadata.json',
        Body=json.dumps(packet).encode()
    )

    # Tải public key
    with open('sender_public.pem', 'rb') as f:
        s3.put_object(
            Bucket=BUCKET_NAME,
            Key='sender_public.pem',
            Body=f.read()
        )

    return "File uploaded to S3"
