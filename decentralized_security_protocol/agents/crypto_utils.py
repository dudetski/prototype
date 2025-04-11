from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import base64

def generate_key_pair():
    """Генерирует пару ключей RSA"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def get_key_str(public_key):
    """Преобразует открытый ключ в строку"""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode('utf-8')  # Return as a string

def sign_message(message, private_key):
    """Подписывает сообщение с использованием закрытого ключа"""
    if isinstance(message, str):
        message = message.encode('utf-8')
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(message, signature, public_key):
    """Проверяет подпись сообщения"""
    if isinstance(message, str):
        message = message.encode('utf-8')
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def hash_object(obj):
    """Создает хеш для объекта"""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(str(obj).encode('utf-8'))
    return digest.finalize().hex()