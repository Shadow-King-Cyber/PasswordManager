import base64
import sqlite3
from datetime import datetime, timezone
from typing import Optional
from pathlib import Path

from src.data.modelos import Cuenta, HistorialEntry, AuditoriaEntry, Categoria
from src.data.persistencia import (
    cargar_vault,
    guardar_vault,
    BaseDatos,
)
from src.core.seguridad import (
    cifrar,
    descifrar,
    generar_contrasena_segura,
    calcular_fortaleza,
)


DIAS_EXPIRACION_DEFAULT = 90


class GestorContrasenas:
    def __init__(self, contrasena_maestra: str):
        self._contrasena_maestra = contrasena_maestra
        self._conn, self._salt = cargar_vault(contrasena_maestra)
        self._bd = BaseDatos(self._conn)

    def _registrar_historial(self, cuenta_id: str, accion: str, detalle: str = None):
        entry = HistorialEntry(cuenta_id=cuenta_id, accion=accion, detalle=detalle)
        self._bd.agregar_historial(entry)

    def _registrar_auditoria(self, evento: str, detalle: str = None):
        entry = AuditoriaEntry(evento=evento, detalle=detalle)
        self._bd.agregar_auditoria(entry)

    def _guardar(self):
        guardar_vault(self._conn, self._contrasena_maestra, self._salt)

    def agregar(
        self,
        servicio: str,
        usuario: str,
        password: str,
        categoria: str = "General",
        notas: str = "",
    ) -> Cuenta:
        password_cifrada = cifrar(password, self._contrasena_maestra, self._salt)
        cuenta = Cuenta(
            servicio=servicio,
            usuario=usuario,
            password_cifrada=password_cifrada,
            categoria=categoria,
            notas=notas,
        )
        self._bd.agregar_cuenta(cuenta)
        self._registrar_historial(cuenta.id, "creada", f"Servicio: {servicio}")
        self._registrar_auditoria("cuenta_agregada", f"Servicio: {servicio}")
        self._guardar()
        return cuenta

    def obtener_password(self, cuenta_id: str) -> str:
        cuenta = self._bd.obtener_cuenta(cuenta_id)
        if not cuenta:
            raise ValueError(f"Cuenta con id {cuenta_id} no encontrada.")
        password = descifrar(cuenta.password_cifrada, self._contrasena_maestra, self._salt)
        self._registrar_auditoria(
            "password_visto", f"Cuenta: {cuenta.servicio} ({cuenta_id[:8]}...)"
        )
        return password

    def obtener_todas(self) -> list[Cuenta]:
        return self._bd.obtener_todas_cuentas()

    def obtener_cuenta(self, cuenta_id: str) -> Optional[Cuenta]:
        return self._bd.obtener_cuenta(cuenta_id)

    def actualizar(
        self,
        cuenta_id: str,
        servicio: str = None,
        usuario: str = None,
        password: str = None,
        categoria: str = None,
        notas: str = None,
    ) -> Cuenta:
        cuenta = self._bd.obtener_cuenta(cuenta_id)
        if not cuenta:
            raise ValueError(f"Cuenta con id {cuenta_id} no encontrada.")

        cambios = []
        if servicio is not None and servicio != cuenta.servicio:
            cambios.append(f"servicio: {cuenta.servicio} -> {servicio}")
            cuenta.servicio = servicio
        if usuario is not None and usuario != cuenta.usuario:
            cambios.append("usuario modificado")
            cuenta.usuario = usuario
        if password is not None:
            cuenta.password_cifrada = cifrar(password, self._contrasena_maestra, self._salt)
            cambios.append("contraseña cambiada")
        if categoria is not None and categoria != cuenta.categoria:
            cambios.append(f"categoría: {cuenta.categoria} -> {categoria}")
            cuenta.categoria = categoria
        if notas is not None and notas != cuenta.notas:
            cambios.append("notas modificadas")
            cuenta.notas = notas

        cuenta.fecha_modificacion = datetime.now(timezone.utc).isoformat()
        cuenta.version += 1
        self._bd.actualizar_cuenta(cuenta)
        if cambios:
            self._registrar_historial(
                cuenta_id, "modificada", "; ".join(cambios)
            )
            self._registrar_auditoria(
                "cuenta_modificada", f"{cuenta.servicio}: {'; '.join(cambios)}"
            )
        self._guardar()
        return cuenta

    def eliminar(self, cuenta_id: str) -> bool:
        cuenta = self._bd.obtener_cuenta(cuenta_id)
        if not cuenta:
            return False
        servicio = cuenta.servicio
        resultado = self._bd.eliminar_cuenta(cuenta_id)
        if resultado:
            self._registrar_historial(
                cuenta_id, "eliminada", f"Servicio: {servicio}"
            )
            self._registrar_auditoria(
                "cuenta_eliminada", f"Servicio: {servicio}"
            )
            self._guardar()
        return resultado

    def buscar(self, termino: str) -> list[Cuenta]:
        return self._bd.buscar_cuentas(termino)

    def generar_y_agregar(
        self,
        servicio: str,
        usuario: str,
        categoria: str = "General",
        longitud: int = 20,
        usar_mayusculas: bool = True,
        usar_digitos: bool = True,
        usar_especiales: bool = True,
        notas: str = "",
    ) -> tuple[Cuenta, str]:
        password = generar_contrasena_segura(
            longitud, usar_mayusculas, usar_digitos, usar_especiales
        )
        cuenta = self.agregar(servicio, usuario, password, categoria, notas)
        return cuenta, password

    # --- Categorías ---
    def obtener_categorias(self) -> list[Categoria]:
        return self._bd.obtener_categorias()

    def agregar_categoria(self, nombre: str, color: str = "#CCCCCC"):
        self._bd.agregar_categoria(nombre, color)
        self._registrar_auditoria("categoria_creada", f"Nombre: {nombre}")
        self._guardar()

    def eliminar_categoria(self, nombre: str):
        self._bd.eliminar_categoria(nombre)
        self._registrar_auditoria("categoria_eliminada", f"Nombre: {nombre}")
        self._guardar()

    def filtrar_por_categoria(self, categoria: str) -> list[Cuenta]:
        return self._bd.filtrar_por_categoria(categoria)

    # --- Historial ---
    def obtener_historial(self, cuenta_id: str, limite: int = 50) -> list[HistorialEntry]:
        return self._bd.obtener_historial(cuenta_id, limite)

    # --- Auditoría ---
    def obtener_auditoria(self, limite: int = 200) -> list[AuditoriaEntry]:
        return self._bd.obtener_auditoria(limite)

    # --- Expiración ---
    def obtener_cuentas_expiradas(self, dias_max: int = DIAS_EXPIRACION_DEFAULT) -> list[Cuenta]:
        return self._bd.obtener_cuentas_expiradas(dias_max)

    def verificar_expiracion(self, dias_max: int = DIAS_EXPIRACION_DEFAULT) -> list[Cuenta]:
        todas = self.obtener_todas()
        return [
            c for c in todas
            if c.dias_antiguedad >= dias_max
        ]

    # --- Estadísticas ---
    def obtener_estadisticas(self) -> dict:
        return self._bd.obtener_estadisticas()

    # --- Fortaleza ---
    def verificar_fortaleza(self, password: str) -> tuple[int, str, list[str]]:
        return calcular_fortaleza(password)

    def obtener_contrasenas_debiles(self) -> list[tuple[Cuenta, str, int]]:
        resultado = []
        for c in self.obtener_todas():
            try:
                password = descifrar(
                    c.password_cifrada, self._contrasena_maestra, self._salt
                )
                puntaje, nivel, _ = calcular_fortaleza(password)
                if puntaje < 60:
                    resultado.append((c, nivel, puntaje))
            except Exception:
                continue
        return resultado

    def registrar_auditoria(self, evento: str, detalle: str = None):
        self._registrar_auditoria(evento, detalle)

    @property
    def conn(self):
        return self._conn

    @property
    def salt(self):
        return self._salt

    def exportar_vault(self, archivo_destino=None):
        from src.utils.exportar import exportar_vault_cifrado
        return exportar_vault_cifrado(self._conn, self._contrasena_maestra, archivo_destino)

    def importar_vault(self, archivo_origen=None):
        from src.utils.exportar import importar_vault_cifrado
        if importar_vault_cifrado(self._conn, self._contrasena_maestra, archivo_origen):
            self._guardar()
            return True
        return False

    def cerrar(self):
        self._guardar()
        self._conn.close()
