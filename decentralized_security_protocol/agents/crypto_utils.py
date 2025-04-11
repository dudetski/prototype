from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import base64
import logging

logger = logging.getLogger(__name__)

def generate_key_pair(key_size=2048):
    """
    Generates an RSA key pair with the specified key size.
    
    Args:
        key_size: Size of the key in bits (default: 2048)
    
    Returns:
        tuple: (private_key, public_key)
    """
    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    except Exception as e:
        logger.error(f"Failed to generate key pair: {e}")
        raise

def get_key_str(public_key):
    """
    Converts a public key to a string representation.
    
    Args:
        public_key: The public key to convert
    
    Returns:
        str: String representation of the public key
    """
    try:
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')
    except Exception as e:
        logger.error(f"Failed to convert public key to string: {e}")
        raise

def load_public_key_from_str(key_str):
    """
    Creates a public key object from a string representation.
    
    Args:
        key_str: String representation of a public key
    
    Returns:
        The loaded public key object
    """
    try:
        key_bytes = key_str.encode('utf-8')
        return serialization.load_pem_public_key(
            key_bytes,
            backend=default_backend()
        )
    except Exception as e:
        logger.error(f"Failed to load public key from string: {e}")
        raise

def sign_message(message, private_key):
    """
    Signs a message using the private key.
    
    Args:
        message: The message to sign (string or bytes)
        private_key: The private key to use for signing
    
    Returns:
        bytes: The signature
    """
    try:
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
    except Exception as e:
        logger.error(f"Failed to sign message: {e}")
        raise

def verify_signature(message, signature, public_key):
    """
    Verifies the signature of a message.
    
    Args:
        message: The message that was signed (string or bytes)
        signature: The signature to verify
        public_key: The public key to use for verification
    
    Returns:
        bool: True if the signature is valid, False otherwise
    """
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
    except InvalidSignature:
        logger.warning("Invalid signature detected")
        return False
    except Exception as e:
        logger.error(f"Error verifying signature: {e}")
        return False

def hash_object(obj):
    """
    Creates a hash for an object.
    
    Args:
        obj: The object to hash
    
    Returns:
        str: Hexadecimal representation of the hash
    """
    try:
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(str(obj).encode('utf-8'))
        return digest.finalize().hex()
    except Exception as e:
        logger.error(f"Failed to hash object: {e}")
        raise

def export_private_key(private_key, password=None):
    """
    Exports a private key to a string format.
    
    Args:
        private_key: The private key to export
        password: Optional password to encrypt the private key
    
    Returns:
        str: String representation of the private key
    """
    try:
        encryption = serialization.BestAvailableEncryption(password.encode('utf-8')) if password else serialization.NoEncryption()
        
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
        return pem.decode('utf-8')
    except Exception as e:
        logger.error(f"Failed to export private key: {e}")
        raise

def load_private_key_from_str(key_str, password=None):
    """
    Loads a private key from a string format.
    
    Args:
        key_str: String representation of the private key
        password: Optional password to decrypt the private key
    
    Returns:
        The loaded private key object
    """
    try:
        key_bytes = key_str.encode('utf-8')
        return serialization.load_pem_private_key(
            key_bytes,
            password=password.encode('utf-8') if password else None,
            backend=default_backend()
        )
    except Exception as e:
        logger.error(f"Failed to load private key from string: {e}")
        raise