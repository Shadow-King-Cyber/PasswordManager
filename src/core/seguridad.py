import os
import base64
import hashlib
import string
import secrets
from typing import Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


ITERACIONES = 600_000
LONGITUD_CLAVE = 32


def generar_salt(tamano: int = 16) -> bytes:
    return os.urandom(tamano)


def derivar_clave(contrasena_maestra: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=LONGITUD_CLAVE,
        salt=salt,
        iterations=ITERACIONES,
    )
    return base64.urlsafe_b64encode(kdf.derive(contrasena_maestra.encode("utf-8")))


def hash_password(contrasena: str) -> tuple[bytes, bytes]:
    salt = generar_salt()
    hash_bytes = hashlib.pbkdf2_hmac(
        "sha256", contrasena.encode("utf-8"), salt, ITERACIONES
    )
    return salt, hash_bytes


def verificar_password(contrasena: str, salt: bytes, hash_almacenado: bytes) -> bool:
    hash_bytes = hashlib.pbkdf2_hmac(
        "sha256", contrasena.encode("utf-8"), salt, ITERACIONES
    )
    return hash_bytes == hash_almacenado


def cifrar(texto: str, clave_maestra: str, salt: bytes) -> str:
    clave = derivar_clave(clave_maestra, salt)
    fernet = Fernet(clave)
    return fernet.encrypt(texto.encode("utf-8")).decode("utf-8")


def descifrar(cifrado: str, clave_maestra: str, salt: bytes) -> str:
    clave = derivar_clave(clave_maestra, salt)
    fernet = Fernet(clave)
    return fernet.decrypt(cifrado.encode("utf-8")).decode("utf-8")


def cifrar_bytes(datos: bytes, clave_maestra: str, salt: bytes) -> bytes:
    clave = derivar_clave(clave_maestra, salt)
    fernet = Fernet(clave)
    return fernet.encrypt(datos)


def descifrar_bytes(datos: bytes, clave_maestra: str, salt: bytes) -> bytes:
    clave = derivar_clave(clave_maestra, salt)
    fernet = Fernet(clave)
    return fernet.decrypt(datos)


def generar_contrasena_segura(
    longitud: int = 20,
    usar_mayusculas: bool = True,
    usar_digitos: bool = True,
    usar_especiales: bool = True,
    evitar_ambiguos: bool = False,
) -> str:
    chars = string.ascii_lowercase
    if usar_mayusculas:
        chars += string.ascii_uppercase
    if usar_digitos:
        chars += string.digits
    if usar_especiales:
        chars += "!@#$%^&*()-_=+[]{}|;:,.<>?"
    if evitar_ambiguos:
        chars = "".join(c for c in chars if c not in "l1Io0O")
    if not chars:
        chars = string.ascii_lowercase
    return "".join(secrets.choice(chars) for _ in range(longitud))


def calcular_fortaleza(contrasena: str) -> tuple[int, str, list[str]]:
    puntuacion = 0
    sugerencias = []

    if len(contrasena) >= 8:
        puntuacion += 20
    if len(contrasena) >= 12:
        puntuacion += 10
    if len(contrasena) >= 16:
        puntuacion += 10
    if any(c.islower() for c in contrasena):
        puntuacion += 10
    if any(c.isupper() for c in contrasena):
        puntuacion += 10
    if any(c.isdigit() for c in contrasena):
        puntuacion += 10
    especiales = any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in contrasena)
    if especiales:
        puntuacion += 15
    variedad = sum([
        any(c.islower() for c in contrasena),
        any(c.isupper() for c in contrasena),
        any(c.isdigit() for c in contrasena),
        especiales,
    ])
    if variedad >= 3:
        puntuacion += 10
    if variedad == 4:
        puntuacion += 5

    if len(contrasena) < 8:
        sugerencias.append("Usa al menos 8 caracteres.")
    if len(contrasena) < 12:
        sugerencias.append("Idealmente 12+ caracteres.")
    if not any(c.isupper() for c in contrasena):
        sugerencias.append("Incluye mayúsculas.")
    if not any(c.isdigit() for c in contrasena):
        sugerencias.append("Incluye números.")
    if not especiales:
        sugerencias.append("Incluye símbolos especiales.")

    if puntuacion >= 80:
        nivel = "Muy fuerte"
    elif puntuacion >= 60:
        nivel = "Fuerte"
    elif puntuacion >= 40:
        nivel = "Media"
    elif puntuacion >= 20:
        nivel = "Débil"
    else:
        nivel = "Muy débil"

    return puntuacion, nivel, sugerencias
