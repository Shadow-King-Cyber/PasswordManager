from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
import uuid


CATEGORIAS_PREDETERMINADAS = {
    "General": "#6c757d",
    "Correo": "#0d6efd",
    "Redes Sociales": "#6f42c1",
    "Banca": "#198754",
    "Trabajo": "#fd7e14",
    "Entretenimiento": "#dc3545",
    "Compras": "#e68533",
    "Salud": "#20c997",
}


@dataclass
class Cuenta:
    servicio: str
    usuario: str
    password_cifrada: str
    categoria: str = "General"
    notas: str = ""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    fecha_creacion: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    fecha_modificacion: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    fecha_expiracion: Optional[str] = None
    version: int = 1

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "servicio": self.servicio,
            "usuario": self.usuario,
            "password_cifrada": self.password_cifrada,
            "categoria": self.categoria,
            "notas": self.notas,
            "fecha_creacion": self.fecha_creacion,
            "fecha_modificacion": self.fecha_modificacion,
            "fecha_expiracion": self.fecha_expiracion,
            "version": self.version,
        }

    @staticmethod
    def from_dict(data: dict) -> "Cuenta":
        return Cuenta(
            id=data.get("id", str(uuid.uuid4())),
            servicio=data["servicio"],
            usuario=data["usuario"],
            password_cifrada=data["password_cifrada"],
            categoria=data.get("categoria", "General"),
            notas=data.get("notas", ""),
            fecha_creacion=data.get(
                "fecha_creacion", datetime.now(timezone.utc).isoformat()
            ),
            fecha_modificacion=data.get(
                "fecha_modificacion", datetime.now(timezone.utc).isoformat()
            ),
            fecha_expiracion=data.get("fecha_expiracion"),
            version=data.get("version", 1),
        )

    @property
    def dias_antiguedad(self) -> int:
        try:
            mod = datetime.fromisoformat(self.fecha_modificacion)
            return (datetime.now(timezone.utc) - mod).days
        except (ValueError, TypeError):
            return 0


@dataclass
class HistorialEntry:
    cuenta_id: str
    accion: str
    detalle: Optional[str] = None
    id: int = 0
    fecha: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "cuenta_id": self.cuenta_id,
            "accion": self.accion,
            "detalle": self.detalle,
            "fecha": self.fecha,
        }


@dataclass
class AuditoriaEntry:
    evento: str
    detalle: Optional[str] = None
    id: int = 0
    fecha: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "evento": self.evento,
            "detalle": self.detalle,
            "fecha": self.fecha,
        }


@dataclass
class Categoria:
    nombre: str
    color: str = "#CCCCCC"

    def to_dict(self) -> dict:
        return {"nombre": self.nombre, "color": self.color}
