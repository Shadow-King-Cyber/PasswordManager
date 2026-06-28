# Arquitectura del Password Manager

## Estructura de Módulos

```
src/
├── main.py               # Punto de entrada
├── ui/
│   └── dashboard.py      # Interfaz gráfica (Tkinter)
├── core/
│   ├── seguridad.py      # Cifrado AES, hashing bcrypt/PBKDF2
│   └── gestor.py         # Lógica CRUD de contraseñas
├── data/
│   ├── modelos.py        # Clases Cuenta y Vault (dataclasses)
│   └── persistencia.py   # Almacenamiento en JSON cifrado
└── utils/
    └── helpers.py        # Validación y generación de contraseñas
```

## Flujo de Datos

1. **Inicio**: `main.py` abre la ventana de login (`VentanaLogin`).
2. **Autenticación**: El usuario ingresa su contraseña maestra. Se verifica contra el hash almacenado en el vault.
3. **Gestión**: `GestorContrasenas` maneja todas las operaciones CRUD. Cada contraseña se cifra con AES-256 (Fernet) antes de almacenarse.
4. **Persistencia**: El vault completo se serializa a JSON, se cifra con la clave maestra y se guarda en `~/.password_manager/vault.json`.

## Seguridad

- **Cifrado AES-256** via Fernet (clave derivada con PBKDF2-HMAC-SHA256, 600,000 iteraciones).
- **Salt único** por vault para la derivación de clave.
- La contraseña maestra **nunca se almacena en texto plano**; solo se guarda un hash (PBKDF2-SHA256 con salt).
- Cada contraseña individual se cifra con la misma clave derivada, pero el salt del vault asegura que dos vaults con la misma clave maestra generen claves diferentes.

## Dependencias

- `cryptography`: cifrado AES-256 (Fernet) y derivación de claves.
- `tkinter`: interfaz gráfica (incluido con Python en Windows).
- `sqlite3` / `json`: persistencia (se usa JSON por simplicidad).
