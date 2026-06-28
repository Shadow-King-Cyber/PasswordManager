import json
import sqlite3
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional

from src.data.modelos import Cuenta, HistorialEntry, AuditoriaEntry, Categoria
from src.core.seguridad import (
    cifrar_bytes,
    descifrar_bytes,
    hash_password,
    generar_salt,
)


ARCHIVO_VAULT = Path.home() / ".password_manager" / "vault.enc"
ARCHIVO_SALT = Path.home() / ".password_manager" / "vault.salt"
CONFIG_DIR = ARCHIVO_VAULT.parent


def _asegurar_directorio():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def vault_existe() -> bool:
    return ARCHIVO_VAULT.exists() and ARCHIVO_SALT.exists()


def _inicializar_db(conn: sqlite3.Connection):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS cuentas (
            id TEXT PRIMARY KEY,
            servicio TEXT NOT NULL,
            usuario TEXT NOT NULL,
            password_cifrada TEXT NOT NULL,
            categoria TEXT DEFAULT 'General',
            notas TEXT DEFAULT '',
            fecha_creacion TEXT NOT NULL,
            fecha_modificacion TEXT NOT NULL,
            fecha_expiracion TEXT,
            version INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS historial (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cuenta_id TEXT NOT NULL,
            accion TEXT NOT NULL,
            detalle TEXT,
            fecha TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS auditoria (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evento TEXT NOT NULL,
            detalle TEXT,
            fecha TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS categorias (
            nombre TEXT PRIMARY KEY,
            color TEXT DEFAULT '#CCCCCC'
        );

        INSERT OR IGNORE INTO categorias (nombre, color) VALUES
            ('General', '#6c757d'),
            ('Correo', '#0d6efd'),
            ('Redes Sociales', '#6f42c1'),
            ('Banca', '#198754'),
            ('Trabajo', '#fd7e14'),
            ('Entretenimiento', '#dc3545'),
            ('Compras', '#e68533'),
            ('Salud', '#20c997');
    """)


def crear_vault(contrasena_maestra: str) -> tuple[bytes, bytes]:
    salt = generar_salt()
    conn = sqlite3.connect(":memory:")
    _inicializar_db(conn)
    datos_db = conn.serialize()
    conn.close()
    return salt, datos_db


def guardar_vault(conn: sqlite3.Connection, contrasena_maestra: str, salt: bytes):
    _asegurar_directorio()
    datos_db = conn.serialize()
    cifrado = cifrar_bytes(datos_db, contrasena_maestra, salt)
    ARCHIVO_VAULT.write_bytes(cifrado)
    ARCHIVO_SALT.write_bytes(salt)


def cargar_vault(contrasena_maestra: str) -> tuple[sqlite3.Connection, bytes]:
    if not vault_existe():
        salt, datos_db = crear_vault(contrasena_maestra)
        conn = sqlite3.connect(":memory:")
        conn.deserialize(datos_db)
        guardar_vault(conn, contrasena_maestra, salt)
        return conn, salt

    cifrado = ARCHIVO_VAULT.read_bytes()
    salt = ARCHIVO_SALT.read_bytes()
    datos_db = descifrar_bytes(cifrado, contrasena_maestra, salt)
    conn = sqlite3.connect(":memory:")
    conn.deserialize(datos_db)
    return conn, salt


def verificar_clave_maestra(contrasena_maestra: str) -> bool:
    if not vault_existe():
        return False
    try:
        cifrado = ARCHIVO_VAULT.read_bytes()
        salt = ARCHIVO_SALT.read_bytes()
        descifrar_bytes(cifrado, contrasena_maestra, salt)
        return True
    except Exception:
        return False


class BaseDatos:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.row_factory = sqlite3.Row

    def _row_a_cuenta(self, row) -> Cuenta:
        return Cuenta(
            id=row["id"],
            servicio=row["servicio"],
            usuario=row["usuario"],
            password_cifrada=row["password_cifrada"],
            categoria=row["categoria"],
            notas=row["notas"],
            fecha_creacion=row["fecha_creacion"],
            fecha_modificacion=row["fecha_modificacion"],
            fecha_expiracion=row["fecha_expiracion"],
            version=row["version"],
        )

    def agregar_cuenta(self, cuenta: Cuenta):
        self.conn.execute(
            """INSERT INTO cuentas
               (id, servicio, usuario, password_cifrada, categoria, notas,
                fecha_creacion, fecha_modificacion, fecha_expiracion, version)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                cuenta.id, cuenta.servicio, cuenta.usuario,
                cuenta.password_cifrada, cuenta.categoria, cuenta.notas,
                cuenta.fecha_creacion, cuenta.fecha_modificacion,
                cuenta.fecha_expiracion, cuenta.version,
            ),
        )
        self.conn.commit()

    def obtener_cuenta(self, cuenta_id: str) -> Optional[Cuenta]:
        row = self.conn.execute(
            "SELECT * FROM cuentas WHERE id = ?", (cuenta_id,)
        ).fetchone()
        return self._row_a_cuenta(row) if row else None

    def obtener_todas_cuentas(self) -> list[Cuenta]:
        rows = self.conn.execute(
            "SELECT * FROM cuentas ORDER BY servicio COLLATE NOCASE"
        ).fetchall()
        return [self._row_a_cuenta(r) for r in rows]

    def actualizar_cuenta(self, cuenta: Cuenta):
        self.conn.execute(
            """UPDATE cuentas SET
               servicio=?, usuario=?, password_cifrada=?, categoria=?, notas=?,
               fecha_modificacion=?, fecha_expiracion=?, version=?
               WHERE id=?""",
            (
                cuenta.servicio, cuenta.usuario, cuenta.password_cifrada,
                cuenta.categoria, cuenta.notas, cuenta.fecha_modificacion,
                cuenta.fecha_expiracion, cuenta.version, cuenta.id,
            ),
        )
        self.conn.commit()

    def eliminar_cuenta(self, cuenta_id: str) -> bool:
        cur = self.conn.execute("DELETE FROM cuentas WHERE id = ?", (cuenta_id,))
        self.conn.commit()
        return cur.rowcount > 0

    def buscar_cuentas(self, termino: str) -> list[Cuenta]:
        patron = f"%{termino}%"
        rows = self.conn.execute(
            """SELECT * FROM cuentas
               WHERE servicio LIKE ? OR usuario LIKE ?
               ORDER BY servicio COLLATE NOCASE""",
            (patron, patron),
        ).fetchall()
        return [self._row_a_cuenta(r) for r in rows]

    def filtrar_por_categoria(self, categoria: str) -> list[Cuenta]:
        rows = self.conn.execute(
            "SELECT * FROM cuentas WHERE categoria = ? ORDER BY servicio COLLATE NOCASE",
            (categoria,),
        ).fetchall()
        return [self._row_a_cuenta(r) for r in rows]

    def obtener_categorias(self) -> list[Categoria]:
        rows = self.conn.execute(
            "SELECT nombre, color FROM categorias ORDER BY nombre"
        ).fetchall()
        return [Categoria(nombre=r["nombre"], color=r["color"]) for r in rows]

    def agregar_categoria(self, nombre: str, color: str = "#CCCCCC"):
        self.conn.execute(
            "INSERT OR IGNORE INTO categorias (nombre, color) VALUES (?, ?)",
            (nombre, color),
        )
        self.conn.commit()

    def eliminar_categoria(self, nombre: str):
        self.conn.execute("DELETE FROM categorias WHERE nombre = ?", (nombre,))
        self.conn.execute(
            "UPDATE cuentas SET categoria = 'General' WHERE categoria = ?",
            (nombre,),
        )
        self.conn.commit()

    def agregar_historial(self, entry: HistorialEntry):
        self.conn.execute(
            "INSERT INTO historial (cuenta_id, accion, detalle, fecha) VALUES (?, ?, ?, ?)",
            (entry.cuenta_id, entry.accion, entry.detalle, entry.fecha),
        )
        self.conn.commit()

    def obtener_historial(self, cuenta_id: str, limite: int = 50) -> list[HistorialEntry]:
        rows = self.conn.execute(
            "SELECT * FROM historial WHERE cuenta_id = ? ORDER BY fecha DESC LIMIT ?",
            (cuenta_id, limite),
        ).fetchall()
        return [
            HistorialEntry(
                id=r["id"], cuenta_id=r["cuenta_id"], accion=r["accion"],
                detalle=r["detalle"], fecha=r["fecha"],
            )
            for r in rows
        ]

    def agregar_auditoria(self, entry: AuditoriaEntry):
        self.conn.execute(
            "INSERT INTO auditoria (evento, detalle, fecha) VALUES (?, ?, ?)",
            (entry.evento, entry.detalle, entry.fecha),
        )
        self.conn.commit()

    def obtener_auditoria(self, limite: int = 200) -> list[AuditoriaEntry]:
        rows = self.conn.execute(
            "SELECT * FROM auditoria ORDER BY fecha DESC LIMIT ?", (limite,)
        ).fetchall()
        return [
            AuditoriaEntry(
                id=r["id"], evento=r["evento"], detalle=r["detalle"], fecha=r["fecha"]
            )
            for r in rows
        ]

    def obtener_cuentas_expiradas(self, dias_max: int = 90) -> list[Cuenta]:
        limite = (datetime.now(timezone.utc) - timedelta(days=dias_max)).isoformat()
        rows = self.conn.execute(
            "SELECT * FROM cuentas WHERE fecha_modificacion < ? ORDER BY fecha_modificacion",
            (limite,),
        ).fetchall()
        return [self._row_a_cuenta(r) for r in rows]

    def obtener_estadisticas(self) -> dict:
        total = self.conn.execute("SELECT COUNT(*) FROM cuentas").fetchone()[0]
        expiradas = len(self.obtener_cuentas_expiradas())
        categorias = self.conn.execute(
            "SELECT categoria, COUNT(*) as cnt FROM cuentas GROUP BY categoria"
        ).fetchall()
        return {
            "total": total,
            "expiradas": expiradas,
            "categorias": {r["categoria"]: r["cnt"] for r in categorias},
        }


