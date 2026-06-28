# Password Manager

Gestor de contraseñas seguro con interfaz gráfica para Windows.

## Ejecución

No requiere instalación ni dependencias externas. Solo descarga y ejecuta:

```
dist\PasswordManager.exe
```

Los datos se guardan automáticamente en `%USERPROFILE%\.password_manager\`.

## Topología del proyecto

```
PasswordManager/
├── assets/
│   └── icon.ico              # Icono de la aplicación
├── src/
│   ├── main.py               # Punto de entrada
│   ├── core/
│   │   ├── gestor.py         # Lógica principal (CRUD de cuentas, historial)
│   │   └── seguridad.py      # Cifrado AES-256, hash, generación y fortaleza
│   ├── data/
│   │   ├── modelos.py        # Dataclasses: Cuenta, Historial, Auditoría, Categoría
│   │   └── persistencia.py   # Base de datos SQLite en memoria cifrada en disco
│   ├── ui/
│   │   └── dashboard.py      # Interfaz gráfica (login, principal, diálogos)
│   └── utils/
│       ├── exportar.py       # Exportar/importar vault cifrado
│       └── helpers.py        # Validaciones, portapapeles, sanitización
├── tests/
│   └── test_seguridad.py     # Pruebas unitarias
├── dist/
│   └── PasswordManager.exe   # Ejecutable portable
├── PasswordManager.spec      # Configuración de PyInstaller
└── requirements.txt          # Dependencias para desarrollo
```

## Funcionalidades

| Función | Descripción |
|---|---|
| **Agregar cuenta** | Guarda servicio, usuario, contraseña y notas |
| **Generar contraseña** | Crea contraseñas seguras configurables (longitud, símbolos, etc.) |
| **Ver contraseña** | Muestra la contraseña con indicador de fortaleza |
| **Copiar** | Copia al portapapeles (se limpia automáticamente a los 30 s) |
| **Buscar** | Filtra por servicio o usuario |
| **Categorías** | Organiza cuentas por categorías con colores personalizados |
| **Historial** | Registro de cambios por cuenta |
| **Auditoría** | Registro de eventos de seguridad |
| **Estadísticas** | Total cuentas, expiradas, débiles |
| **Exportar/Importar** | Backup cifrado del vault |
| **Bloqueo automático** | Bloquea la sesión tras inactividad |
| **Modo oscuro** | Tema claro/oscuro |

## Seguridad

- Cifrado AES-256 vía **Fernet** (cryptography)
- Derivación de clave con **PBKDF2-HMAC-SHA256** (600.000 iteraciones)
- Vault completo cifrado en disco (`~/.password_manager/vault.enc`)
- Contraseña maestra hasheada con salt
- Límite de intentos de login con retraso progresivo
- Portapapeles limpiado automáticamente

## Desarrollo

### Requisitos

- Python 3.10+
- pip

### Instalación

```bash
pip install -r requirements.txt
```

### Ejecutar desde código

```bash
python -m src.main
```

### Pruebas

```bash
python -m pytest tests/
```

### Generar ejecutable

```bash
python -m PyInstaller PasswordManager.spec --clean
```

El ejecutable se genera en `dist\PasswordManager.exe` y es completamente portable.
