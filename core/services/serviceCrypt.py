
from cryptography.fernet import Fernet
import base64

# schemas
from core.schemas import app_fernet_private_key


class service_cryptography():
    def __init__(self):
        self.key = str(app_fernet_private_key).encode()
        self.fernet = Fernet(self.key)

    def set_key(self, keygen):
        key = base64.urlsafe_b64encode(keygen)
        self.fernet = Fernet(key)

    def text_to_crypt(self, plaintext):
        if not plaintext:
            return None
        return self.fernet.encrypt(plaintext.encode()).decode()
    
    def crypt_to_text(self, hashed):
        if not hashed:
            return None
        return self.fernet.decrypt(hashed.encode()).decode()