# app/security.py
import bcrypt
from passlib.context import CryptContext
from passlib.exc import UnknownHashError

# Use Argon2 (or your preferred modern scheme) for NEW hashes
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

def _is_bcrypt_hash(h: str) -> bool:
    return isinstance(h, str) and (h.startswith("$2a$") or h.startswith("$2b$") or h.startswith("$2y$"))

def verify_password(password: str, password_hash: str) -> bool:
    try:
        if _is_bcrypt_hash(password_hash):
            # Avoid Passlib's bcrypt backend/init entirely
            return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
        return pwd_context.verify(password, password_hash)
    except (ValueError, UnknownHashError, Exception):
        # Normalize ANY crypto error to False; never bubble a 500
        return False

def hash_password(password: str) -> str:
    return pwd_context.hash(password)




# from passlib.context import CryptContext

# # Prefer bcrypt_sha256 to avoid 72-byte password limit and wrap bugs
# pwd_context = CryptContext(
#     schemes=["bcrypt_sha256", "bcrypt"],
#     deprecated=["bcrypt"],  # bcrypt still accepted for old hashes
# )

# def get_password_hash(password: str) -> str:
#     return pwd_context.hash(password)

# def verify_password(password: str, password_hash: str) -> bool:
#     return pwd_context.verify(password, password_hash)

# # Backward-compatibility for existing imports in code (e.g., from app.security import hash_password)
# def hash_password(password: str) -> str:
#     return get_password_hash(password)
