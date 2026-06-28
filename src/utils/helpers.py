import re
import threading
import subprocess
import sys
from typing import Optional


SEGUNDOS_CLIPBOARD = 30


def validar_servicio(servicio: str) -> tuple[bool, str]:
    if not servicio or not servicio.strip():
        return False, "El nombre del servicio no puede estar vacío."
    if len(servicio) > 100:
        return False, "El nombre del servicio es demasiado largo (máx. 100 caracteres)."
    return True, ""


def validar_usuario(usuario: str) -> tuple[bool, str]:
    if not usuario or not usuario.strip():
        return False, "El nombre de usuario no puede estar vacío."
    if len(usuario) > 255:
        return False, "El nombre de usuario es demasiado largo (máx. 255 caracteres)."
    return True, ""


def validar_contrasena(contrasena: str) -> tuple[bool, str]:
    if not contrasena:
        return False, "La contraseña no puede estar vacía."
    if len(contrasena) < 4:
        return False, "La contraseña debe tener al menos 4 caracteres."
    return True, ""


def validar_contrasena_maestra(contrasena: str) -> tuple[bool, str]:
    if not contrasena:
        return False, "La contraseña maestra no puede estar vacía."
    if len(contrasena) < 8:
        return False, "La contraseña maestra debe tener al menos 8 caracteres."
    return True, ""


def sanitizar_entrada(texto: str) -> str:
    return texto.strip()


def copiar_al_portapapeles(texto: str, temporizador: int = SEGUNDOS_CLIPBOARD):
    try:
        import pyperclip
        pyperclip.copy(texto)
    except ImportError:
        try:
            subprocess.run(
                ["clip"],
                input=texto.strip().encode("utf-8"),
                shell=False,
                check=True,
            )
        except Exception:
            return
    if temporizador > 0:
        threading.Timer(temporizador, limpiar_portapapeles).start()


def limpiar_portapapeles():
    try:
        import pyperclip
        pyperclip.copy("")
    except ImportError:
        try:
            subprocess.run(["clip"], input=b"", shell=False, check=True)
        except Exception:
            pass


def formatear_tiempo_inactivo(segundos: int) -> str:
    if segundos < 60:
        return f"{segundos} segundos"
    minutos = segundos // 60
    if minutos < 60:
        return f"{minutos} minutos" if minutos > 1 else "1 minuto"
    horas = minutos // 60
    return f"{horas} horas" if horas > 1 else "1 hora"

