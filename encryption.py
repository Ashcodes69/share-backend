import base64
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id


def derive_cipher(password: str, salt: bytes):
    kdf = Argon2id(salt, length=32, iterations=2, lanes=4, memory_cost=131072)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    cipher = Fernet(key)
    return cipher


def encrypt_file(file_data: bytes, filename: str, password: str) -> bytes:
    salt = os.urandom(16)

    cipher = derive_cipher(password, salt)

    filename_bytes = filename.encode("utf-8")
    filename_len_bytes = len(filename_bytes).to_bytes(2, byteorder="big")

    payload = filename_len_bytes + filename_bytes + file_data

    encrypted_payload = cipher.encrypt(payload)

    return b"DEAD" + salt + encrypted_payload


def decrypt_file(encrypted_data: bytes, password: str) -> tuple[str, bytes]:
    header_len = 4
    salt_len = 16
    min_len = header_len + salt_len

    if len(encrypted_data) < min_len or not encrypted_data.startswith(b"DEAD"):
        raise ValueError("Invalid format: Missing DEAD header or turncate data.")

    salt = encrypted_data[header_len : header_len + salt_len]

    ciphertext = encrypted_data[min_len:]
    if not ciphertext:
        raise ValueError("Malformed data: ciphertext is missing.")

    cipher = derive_cipher(password, salt)

    try:
        decrypted_payload = cipher.decrypt(ciphertext)
    except InvalidToken:
        raise InvalidToken(
            "Decryption failed: incorrect password or currupted ciphertext."
        )

    if len(decrypted_payload) < 2:
        raise ValueError("Malformed payload: Missing filename length header.")

    filename_lwn = int.from_bytes(decrypted_payload[:2], byteorder="big")
    expected_meta_len = 2 + filename_lwn

    if len(decrypted_payload) < expected_meta_len:
        raise ValueError("Malformed payload: turncated filename data.")

    try:
        filename = decrypted_payload[2:expected_meta_len].decode("utf-8")
    except UnicodeDecodeError as err:
        raise ValueError("Malformed payload: filename is not valid utf-8.") from err

    file_data = decrypted_payload[expected_meta_len:]

    return filename, file_data
