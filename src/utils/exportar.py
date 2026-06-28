import json
import base64
import sqlite3
from pathlib import Path
from typing import Optional
from tkinter import filedialog, messagebox

from src.core.seguridad import cifrar_bytes, descifrar_bytes, generar_salt


EXTENSION = ".enc"


def exportar_vault_cifrado(
    conn,
    contrasena_maestra: str,
    archivo_destino: Optional[str] = None,
) -> Optional[str]:
    if not archivo_destino:
        archivo_destino = filedialog.asksaveasfilename(
            defaultextension=EXTENSION,
            filetypes=[("Archivo cifrado", EXTENSION)],
            title="Exportar vault cifrado",
        )
        if not archivo_destino:
            return None

    datos_db = conn.serialize()
    export_salt = generar_salt()
    cifrado = cifrar_bytes(datos_db, contrasena_maestra, export_salt)

    paquete = {
        "version": 1,
        "salt": base64.urlsafe_b64encode(export_salt).decode("utf-8"),
        "data": base64.urlsafe_b64encode(cifrado).decode("utf-8"),
    }

    Path(archivo_destino).write_text(
        json.dumps(paquete, indent=2), encoding="utf-8"
    )
    return archivo_destino


def importar_vault_cifrado(
    conn,
    contrasena_maestra: str,
    archivo_origen: Optional[str] = None,
) -> bool:
    if not archivo_origen:
        archivo_origen = filedialog.askopenfilename(
            defaultextension=EXTENSION,
            filetypes=[("Archivo cifrado", EXTENSION)],
            title="Importar vault cifrado",
        )
        if not archivo_origen:
            return False

    try:
        paquete = json.loads(Path(archivo_origen).read_text(encoding="utf-8"))
        export_salt = base64.urlsafe_b64decode(paquete["salt"].encode("utf-8"))
        cifrado = base64.urlsafe_b64decode(paquete["data"].encode("utf-8"))
        datos_db = descifrar_bytes(cifrado, contrasena_maestra, export_salt)

        otra = sqlite3.connect(":memory:")
        otra.deserialize(datos_db)
        otra.backup(conn)
        otra.close()
        conn.commit()
        return True
    except Exception as e:
        messagebox.showerror("Error de importación", f"No se pudo importar: {e}")
        return False
