import tkinter as tk
from src.ui.dashboard import VentanaLogin, VentanaPrincipal, _cargar_config, SEGUNDOS_BLOQUEO_AUTO
from pathlib import Path
import json
import traceback
import sys


CONFIG_DIR = Path.home() / ".password_manager"
LOG_ERROR = CONFIG_DIR / "error.log"
_RUTA_BASE = Path(getattr(sys, "_MEIPASS", Path.cwd()))


def _inicializar_config():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    config = _cargar_config()
    cambios = False
    if "modo_oscuro" not in config:
        config["modo_oscuro"] = False
        cambios = True
    if "tiempo_bloqueo" not in config:
        config["tiempo_bloqueo"] = SEGUNDOS_BLOQUEO_AUTO
        cambios = True
    if cambios:
        (CONFIG_DIR / "config.json").write_text(
            json.dumps(config, indent=2), encoding="utf-8"
        )


def _config_root_para_login(root):
    root.title("Password Manager")
    root.geometry("300x200")
    root.minsize(300, 200)


def main():
    LOG_ERROR.parent.mkdir(parents=True, exist_ok=True)
    try:
        _inicializar_config()

        root = tk.Tk()
        _config_root_para_login(root)

        try:
            icono = _RUTA_BASE / "assets" / "icon.ico"
            if icono.exists():
                root.iconbitmap(str(icono))
        except Exception:
            pass

        login = VentanaLogin(root)
        root.wait_window(login)

        if login.gestor:
            for w in root.winfo_children():
                w.destroy()
            app = VentanaPrincipal(root, login.gestor)
            root.protocol("WM_DELETE_WINDOW", lambda: _salir(root, app))
            try:
                root.mainloop()
            except KeyboardInterrupt:
                _salir(root, app)
        else:
            root.destroy()
    except Exception:
        with open(LOG_ERROR, "w", encoding="utf-8") as f:
            traceback.print_exc(file=f)


def _salir(root, app=None):
    if app and hasattr(app, "gestor"):
        try:
            app.gestor.cerrar()
        except Exception:
            pass
    root.destroy()


if __name__ == "__main__":
    main()
