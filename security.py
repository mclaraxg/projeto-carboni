from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re


PASSWORD_POLICY_DESCRIPTION = (
    "A senha deve ter no mínimo 8 caracteres, com maiúscula, minúscula, número e caractere especial."
)


def is_password_strong(password: str) -> bool:
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[^A-Za-z0-9]", password):
        return False
    return True


def hash_password(password: str) -> tuple[str, str]:
    salt = os.urandom(16)
    derived_key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310000)
    return base64.b64encode(salt).decode("utf-8"), base64.b64encode(derived_key).decode("utf-8")


def verify_password(password: str, salt_b64: str, expected_hash_b64: str) -> bool:
    salt = base64.b64decode(salt_b64.encode("utf-8"))
    expected_hash = base64.b64decode(expected_hash_b64.encode("utf-8"))
    derived_key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310000)
    return hmac.compare_digest(derived_key, expected_hash)