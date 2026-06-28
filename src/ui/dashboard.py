import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, colorchooser
from tkinter.scrolledtext import ScrolledText
from datetime import datetime, timezone
import json
from pathlib import Path

from src.core.gestor import GestorContrasenas
from src.data.persistencia import verificar_clave_maestra, vault_existe
from src.utils.helpers import (
    validar_servicio,
    validar_usuario,
    validar_contrasena,
    validar_contrasena_maestra,
    sanitizar_entrada,
    copiar_al_portapapeles,
    formatear_tiempo_inactivo,
)
from src.core.seguridad import generar_contrasena_segura, calcular_fortaleza


ARCHIVO_CONFIG = Path.home() / ".password_manager" / "config.json"
INTENTOS_MAX = 5
SEGUNDOS_BLOQUEO_AUTO = 300
DIAS_EXPIRACION = 90


class Tema:
    CLARO = {
        "bg": "#f5f5f5",
        "fg": "#212529",
        "select": "#0d6efd",
        "card": "#ffffff",
        "card_border": "#dee2e6",
        "btn": "#0d6efd",
        "btn_fg": "#ffffff",
        "danger": "#dc3545",
        "success": "#198754",
        "warning": "#ffc107",
        "entry_bg": "#ffffff",
        "tree_bg": "#ffffff",
        "tree_fg": "#212529",
        "tree_select": "#0d6efd",
    }
    OSCURO = {
        "bg": "#1e1e2e",
        "fg": "#cdd6f4",
        "select": "#89b4fa",
        "card": "#313244",
        "card_border": "#45475a",
        "btn": "#89b4fa",
        "btn_fg": "#1e1e2e",
        "danger": "#f38ba8",
        "success": "#a6e3a1",
        "warning": "#f9e2af",
        "entry_bg": "#45475a",
        "tree_bg": "#313244",
        "tree_fg": "#cdd6f4",
        "tree_select": "#89b4fa",
    }


def _cargar_config():
    if ARCHIVO_CONFIG.exists():
        try:
            return json.loads(ARCHIVO_CONFIG.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"modo_oscuro": False, "tiempo_bloqueo": SEGUNDOS_BLOQUEO_AUTO}


def _guardar_config(config: dict):
    ARCHIVO_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    ARCHIVO_CONFIG.write_text(json.dumps(config, indent=2), encoding="utf-8")


class VentanaLogin(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.gestor = None
        self._intentos = 0
        config = _cargar_config()
        self._modo_oscuro = config.get("modo_oscuro", False)
        self._tema = Tema.OSCURO if self._modo_oscuro else Tema.CLARO
        self._configurar_ventana()
        self._crear_widgets()

    def _configurar_ventana(self):
        self.title("Password Manager - Inicio de Sesión")
        self.geometry("480x380")
        self.resizable(False, False)
        self.transient(self.parent)
        self.grab_set()
        self.configure(bg=self._tema["bg"])

    def _estilo(self):
        style = ttk.Style()
        style.theme_use("clam")
        bg = self._tema["bg"]
        fg = self._tema["fg"]
        entry_bg = self._tema["entry_bg"]
        btn = self._tema["btn"]
        btn_fg = self._tema["btn_fg"]
        style.configure("TFrame", background=bg)
        style.configure("TLabel", background=bg, foreground=fg)
        style.configure("TButton", background=btn, foreground=btn_fg, borderwidth=1)
        style.map("TButton", background=[("active", "#6c757d")])
        style.configure("TEntry", fieldbackground=entry_bg, foreground=fg)
        style.configure("Header.TLabel", background=bg, foreground=fg, font=("Segoe UI", 18, "bold"))
        style.configure("Sub.TLabel", background=bg, foreground=fg, font=("Segoe UI", 10))

    def _crear_widgets(self):
        self._estilo()
        frame = ttk.Frame(self, padding=30)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="🔐 Password Manager", style="Header.TLabel").pack(pady=(0, 5))
        ttk.Label(frame, text="Ingrese su contraseña maestra", style="Sub.TLabel").pack(pady=(0, 5))

        self._lbl_estado = tk.Label(frame, text="", fg=self._tema["danger"], bg=self._tema["bg"])
        self._lbl_estado.pack(pady=(0, 5))

        ttk.Label(frame, text="Contraseña maestra:").pack(anchor=tk.W)
        self.entry_password = ttk.Entry(frame, show="*", font=("Segoe UI", 12))
        self.entry_password.pack(fill=tk.X, pady=(5, 15), ipady=4)
        self.entry_password.focus_set()

        frame_botones = ttk.Frame(frame)
        frame_botones.pack(fill=tk.X)

        self.btn_ingresar = ttk.Button(
            frame_botones, text="Ingresar", command=self._ingresar
        )
        self.btn_ingresar.pack(side=tk.LEFT, padx=(0, 5), fill=tk.X, expand=True)

        self.btn_crear = ttk.Button(
            frame_botones, text="Crear vault", command=self._crear_nuevo_vault
        )
        self.btn_crear.pack(side=tk.RIGHT, padx=(5, 0), fill=tk.X, expand=True)

        self.bind("<Return>", lambda e: self._ingresar())

    def _retraso_progresivo(self) -> int:
        if self._intentos <= 3:
            return 0
        if self._intentos == 4:
            return 5
        if self._intentos == 5:
            return 15
        return 60

    def _ingresar(self):
        password = self.entry_password.get()
        if self._intentos >= INTENTOS_MAX:
            self._lbl_estado.config(
                text="Demasiados intentos. Reinicia la aplicación."
            )
            self.btn_ingresar.config(state=tk.DISABLED)
            return

        if not vault_existe():
            messagebox.showerror("Error", "No existe ningún vault. Cree uno nuevo.")
            return

        retraso = self._retraso_progresivo()
        if retraso > 0:
            self._lbl_estado.config(
                text=f"Demasiados intentos. Espere {retraso} segundos..."
            )
            self.after(retraso * 1000, self._intentar_acceso, password)
            self._intentos += 1
            return

        self._intentar_acceso(password)

    def _intentar_acceso(self, password):
        if verificar_clave_maestra(password):
            try:
                self.gestor = GestorContrasenas(password)
                self._guardar_ultimo_acceso()
                self.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Error al abrir el vault: {e}")
                self._intentos += 1
        else:
            self._intentos += 1
            restantes = INTENTOS_MAX - self._intentos
            msg = f"Contraseña maestra incorrecta. Intentos restantes: {max(0, restantes)}"
            self._lbl_estado.config(text=msg)
            self.entry_password.delete(0, tk.END)
            self.entry_password.focus_set()

    def _crear_nuevo_vault(self):
        password = self.entry_password.get()
        valido, msg = validar_contrasena_maestra(password)
        if not valido:
            messagebox.showerror("Error", msg)
            return
        if vault_existe():
            if not messagebox.askyesno(
                "Confirmar", "Ya existe un vault. ¿Desea sobrescribirlo?"
            ):
                return
        try:
            self.gestor = GestorContrasenas(password)
            self._guardar_ultimo_acceso()
            messagebox.showinfo("Éxito", "Vault creado correctamente.")
            self.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo crear el vault: {e}")

    def _guardar_ultimo_acceso(self):
        config = _cargar_config()
        config["ultimo_acceso"] = datetime.now(timezone.utc).isoformat()
        _guardar_config(config)


class VentanaPrincipal(ttk.Frame):
    def __init__(self, parent, gestor: GestorContrasenas):
        super().__init__(parent)
        self.parent = parent
        self.gestor = gestor
        config = _cargar_config()
        self._modo_oscuro = config.get("modo_oscuro", False)
        self._tema = Tema.OSCURO if self._modo_oscuro else Tema.CLARO
        self._tiempo_bloqueo = config.get("tiempo_bloqueo", SEGUNDOS_BLOQUEO_AUTO)
        self._ultima_actividad = datetime.now()
        self._bloqueado = False
        self._configurar_ventana()
        self._crear_widgets()
        self._aplicar_tema()
        self._cargar_tabla()
        self._iniciar_timer_bloqueo()
        self._verificar_expiracion_al_inicio()
        self._verificar_contrasenas_debiles()

    def _configurar_ventana(self):
        self.parent.title("Password Manager")
        self.parent.geometry("1100x700")
        self.parent.minsize(900, 500)
        self.parent.resizable(True, True)
        self.pack(fill=tk.BOTH, expand=True)

    def _aplicar_tema(self):
        style = ttk.Style()
        style.theme_use("clam")
        bg = self._tema["bg"]
        fg = self._tema["fg"]
        card = self._tema["card"]
        entry_bg = self._tema["entry_bg"]
        btn = self._tema["btn"]
        btn_fg = self._tema["btn_fg"]
        tree_bg = self._tema["tree_bg"]
        tree_fg = self._tema["tree_fg"]
        tree_sel = self._tema["tree_select"]

        style.configure("TFrame", background=bg)
        style.configure("TLabel", background=bg, foreground=fg)
        style.configure("Card.TFrame", background=card, relief=tk.SOLID, borderwidth=1)
        style.configure(
            "Card.TLabel", background=card, foreground=fg, font=("Segoe UI", 9)
        )
        style.configure("TButton", background=btn, foreground=btn_fg, borderwidth=1)
        style.map("TButton",
                  background=[("active", "#6c757d" if not self._modo_oscuro else "#585b70")])
        style.configure("TEntry", fieldbackground=entry_bg, foreground=fg)
        style.configure("TSpinbox", fieldbackground=entry_bg, foreground=fg)
        style.map("Treeview",
                  background=[("selected", tree_sel)],
                  foreground=[("selected", "#ffffff")])
        style.configure("Treeview", background=tree_bg, foreground=tree_fg,
                        fieldbackground=tree_bg)
        style.configure("Treeview.Heading", background=card, foreground=fg,
                        font=("Segoe UI", 9, "bold"))
        style.configure("Header.TLabel", background=bg, foreground=fg,
                        font=("Segoe UI", 16, "bold"))
        style.configure("Status.TLabel", background=bg, foreground=fg,
                        font=("Segoe UI", 9))
        self._aplicar_tema_scrollbars()

    def _aplicar_tema_scrollbars(self):
        self.parent.tk.call(
            "ttk::style", "configure", "Vertical.TScrollbar",
            "-background", self._tema["card"],
            "-troughcolor", self._tema["bg"],
            "-arrowcolor", self._tema["fg"],
        )

    def _crear_widgets(self):
        panel_superior = ttk.Frame(self, padding=(15, 10, 15, 5))
        panel_superior.pack(fill=tk.X)

        frame_titulo = ttk.Frame(panel_superior)
        frame_titulo.pack(side=tk.LEFT)

        ttk.Label(frame_titulo, text="Password Manager", style="Header.TLabel").pack(
            anchor=tk.W
        )
        self._lbl_estado = ttk.Label(
            frame_titulo, text="", style="Status.TLabel"
        )
        self._lbl_estado.pack(anchor=tk.W)

        frame_acciones = ttk.Frame(panel_superior)
        frame_acciones.pack(side=tk.RIGHT)

        self._btn_tema = ttk.Button(frame_acciones, text="🌙" if not self._modo_oscuro else "☀️",
                                     command=self._alternar_tema, width=3)
        self._btn_tema.pack(side=tk.LEFT, padx=2)
        ttk.Button(frame_acciones, text="📊", command=self._mostrar_estadisticas,
                   width=3).pack(side=tk.LEFT, padx=2)
        ttk.Button(frame_acciones, text="📤", command=self._exportar_vault,
                   width=3).pack(side=tk.LEFT, padx=2)
        ttk.Button(frame_acciones, text="📥", command=self._importar_vault,
                   width=3).pack(side=tk.LEFT, padx=2)
        ttk.Button(frame_acciones, text="🔒 Bloquear",
                   command=self._bloquear).pack(side=tk.LEFT, padx=2)

        panel_busqueda = ttk.Frame(self, padding=(15, 0, 15, 5))
        panel_busqueda.pack(fill=tk.X)

        self.entry_buscar = ttk.Entry(panel_busqueda, width=35, font=("Segoe UI", 10))
        self.entry_buscar.pack(side=tk.LEFT, padx=(0, 5), ipady=3)
        self.entry_buscar.insert(0, "Buscar...")
        self.entry_buscar.bind("<FocusIn>", lambda e: self._limpiar_placeholder())
        self.entry_buscar.bind("<FocusOut>", lambda e: self._restaurar_placeholder())
        self.entry_buscar.bind("<KeyRelease>", lambda e: self._filtrar_tabla())

        self._combo_categoria = ttk.Combobox(
            panel_busqueda, state="readonly", width=18, font=("Segoe UI", 9)
        )
        self._combo_categoria.pack(side=tk.LEFT, padx=5)
        self._combo_categoria.bind("<<ComboboxSelected>>", self._filtrar_por_categoria)

        ttk.Button(panel_busqueda, text="➕ Categoría",
                   command=self._agregar_categoria_dialogo).pack(side=tk.LEFT, padx=2)

        panel_botones = ttk.Frame(self, padding=(15, 5))
        panel_botones.pack(fill=tk.X)

        for texto, comando, color in [
            ("➕ Agregar", self._agregar_cuenta, self._tema["btn"]),
            ("✏️ Editar", self._editar_cuenta, self._tema["warning"]),
            ("🗑️ Eliminar", self._eliminar_cuenta, self._tema["danger"]),
            ("👁️ Ver", self._ver_password, self._tema["btn"]),
            ("📋 Copiar", self._copiar_password, self._tema["success"]),
            ("🔍 Auditoría", self._mostrar_auditoria, self._tema["btn"]),
        ]:
            btn = tk.Button(
                panel_botones,
                text=texto,
                command=comando,
                bg=color,
                fg=self._tema["btn_fg"],
                font=("Segoe UI", 9, "bold"),
                relief=tk.FLAT,
                padx=12,
                pady=4,
                cursor="hand2",
            )
            btn.pack(side=tk.LEFT, padx=(0, 5))
            btn.bind("<Enter>", lambda e, b=btn: b.config(bg="#6c757d"))
            btn.bind("<Leave>", lambda e, b=btn, c=color: b.config(bg=c))

        frame_principal = ttk.Frame(self, padding=(15, 5, 15, 10))
        frame_principal.pack(fill=tk.BOTH, expand=True)

        frame_tabla = ttk.Frame(frame_principal)
        frame_tabla.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        columnas = ("servicio", "usuario", "categoria", "notas", "id")
        self.tabla = ttk.Treeview(
            frame_tabla, columns=columnas, show="headings",
            selectmode="browse", height=20,
        )
        self.tabla.heading("servicio", text="Servicio")
        self.tabla.heading("usuario", text="Usuario")
        self.tabla.heading("categoria", text="Categoría")
        self.tabla.heading("notas", text="Notas")
        self.tabla.heading("id", text="ID")
        self.tabla.column("servicio", width=200, minwidth=100)
        self.tabla.column("usuario", width=200, minwidth=100)
        self.tabla.column("categoria", width=120, minwidth=80)
        self.tabla.column("notas", width=250, minwidth=100)
        self.tabla.column("id", width=0, stretch=False, minwidth=0)

        scroll_v = ttk.Scrollbar(
            frame_tabla, orient=tk.VERTICAL, command=self.tabla.yview
        )
        self.tabla.configure(yscrollcommand=scroll_v.set)
        self.tabla.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll_v.pack(side=tk.RIGHT, fill=tk.Y)
        self.tabla.bind("<Double-1>", lambda e: self._ver_password())

        frame_detalle = ttk.Frame(frame_principal, width=280)
        frame_detalle.pack(side=tk.RIGHT, fill=tk.Y, padx=(10, 0))
        self._crear_panel_detalle(frame_detalle)

        self.bind_all("<KeyPress>", self._reset_actividad)
        self.bind_all("<ButtonPress>", self._reset_actividad)

    def _crear_panel_detalle(self, parent):
        card = tk.Frame(parent, bg=self._tema["card"],
                        highlightbackground=self._tema["card_border"],
                        highlightthickness=1)
        card.pack(fill=tk.BOTH, expand=True)

        tk.Label(
            card, text="Detalles", font=("Segoe UI", 12, "bold"),
            bg=self._tema["card"], fg=self._tema["fg"]
        ).pack(pady=(10, 5))

        self._detalle_text = tk.Text(
            card, height=15, width=30, wrap=tk.WORD,
            bg=self._tema["card"], fg=self._tema["fg"],
            font=("Segoe UI", 9), relief=tk.FLAT,
            borderwidth=0, state=tk.DISABLED,
        )
        self._detalle_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        tk.Button(
            card, text="Ver historial",
            command=self._ver_historial,
            bg=self._tema["btn"], fg=self._tema["btn_fg"],
            font=("Segoe UI", 9, "bold"), relief=tk.FLAT,
            padx=10, pady=4, cursor="hand2",
        ).pack(pady=(0, 10))

    def _actualizar_detalle(self, cuenta_id: str = None):
        self._detalle_text.config(state=tk.NORMAL)
        self._detalle_text.delete("1.0", tk.END)
        if cuenta_id:
            cuenta = self.gestor.obtener_cuenta(cuenta_id)
            if cuenta:
                info = (
                    f"Servicio: {cuenta.servicio}\n"
                    f"Usuario: {cuenta.usuario}\n"
                    f"Categoría: {cuenta.categoria}\n"
                    f"Antigüedad: {cuenta.dias_antiguedad} días\n"
                    f"Creado: {cuenta.fecha_creacion[:10]}\n"
                    f"Modificado: {cuenta.fecha_modificacion[:10]}"
                )
                self._detalle_text.insert(tk.END, info)
        self._detalle_text.config(state=tk.DISABLED)

    def _limpiar_placeholder(self):
        if self.entry_buscar.get() == "Buscar...":
            self.entry_buscar.delete(0, tk.END)

    def _restaurar_placeholder(self):
        if not self.entry_buscar.get():
            self.entry_buscar.insert(0, "Buscar...")

    def _reset_actividad(self, event=None):
        self._ultima_actividad = datetime.now()

    def _iniciar_timer_bloqueo(self):
        if self._tiempo_bloqueo <= 0:
            return
        ahora = datetime.now()
        delta = (ahora - self._ultima_actividad).total_seconds()
        restante = max(0, self._tiempo_bloqueo - delta)
        self._lbl_estado.config(
            text=f"Bloqueo auto: {formatear_tiempo_inactivo(int(restante))}"
        )
        if restante <= 0 and not self._bloqueado:
            self._bloquear()
        self.after(1000, self._iniciar_timer_bloqueo)

    def _bloquear(self):
        self._bloqueado = True
        self.gestor.cerrar()
        self.parent.withdraw()
        login = VentanaLogin(self.parent)
        login._modo_oscuro = self._modo_oscuro
        login._tema = Tema.OSCURO if self._modo_oscuro else Tema.CLARO
        self.parent.wait_window(login)
        if login.gestor:
            self.gestor = login.gestor
            self._bloqueado = False
            self._ultima_actividad = datetime.now()
            self._cargar_tabla()
            self._actualizar_categorias()
            self.parent.deiconify()
        else:
            self.parent.destroy()

    def _alternar_tema(self):
        self._modo_oscuro = not self._modo_oscuro
        self._tema = Tema.OSCURO if self._modo_oscuro else Tema.CLARO
        self._btn_tema.config(text="🌙" if not self._modo_oscuro else "☀️")
        config = _cargar_config()
        config["modo_oscuro"] = self._modo_oscuro
        _guardar_config(config)
        self._aplicar_tema()
        self._cargar_tabla()
        self._actualizar_detalle()

    def _actualizar_categorias(self):
        categorias = self.gestor.obtener_categorias()
        valores = ["Todas"] + [c.nombre for c in categorias]
        self._combo_categoria["values"] = valores
        if not self._combo_categoria.get():
            self._combo_categoria.set("Todas")

    def _cargar_tabla(self, cuentas=None):
        for item in self.tabla.get_children():
            self.tabla.delete(item)
        if cuentas is None:
            cuentas = self.gestor.obtener_todas()
        for c in cuentas:
            self.tabla.insert(
                "", tk.END,
                values=(c.servicio, c.usuario, c.categoria, c.notas[:60], c.id),
                tags=(c.categoria,),
            )
        self._actualizar_categorias()

    def _filtrar_tabla(self, event=None):
        termino = self.entry_buscar.get()
        if not termino or termino == "Buscar...":
            self._cargar_tabla()
        else:
            self._cargar_tabla(self.gestor.buscar(termino))

    def _filtrar_por_categoria(self, event=None):
        cat = self._combo_categoria.get()
        if not cat or cat == "Todas":
            self._cargar_tabla()
        else:
            self._cargar_tabla(self.gestor.filtrar_por_categoria(cat))

    def _obtener_seleccionada(self) -> str | None:
        seleccion = self.tabla.selection()
        if not seleccion:
            messagebox.showwarning("Seleccionar", "Seleccione una cuenta primero.")
            return None
        return self.tabla.item(seleccion[0], "values")[4]

    def _agregar_cuenta(self):
        dialogo = DialogoCuenta(
            self.parent, titulo="Agregar cuenta",
            categorias=[c.nombre for c in self.gestor.obtener_categorias()],
        )
        if dialogo.resultado:
            servicio, usuario, password, categoria, notas = dialogo.resultado
            try:
                self.gestor.agregar(servicio, usuario, password, categoria, notas)
                self._cargar_tabla()
                messagebox.showinfo("Éxito", "Cuenta agregada correctamente.")
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo agregar: {e}")

    def _editar_cuenta(self):
        cuenta_id = self._obtener_seleccionada()
        if not cuenta_id:
            return
        cuenta = self.gestor.obtener_cuenta(cuenta_id)
        if not cuenta:
            return
        categorias = [c.nombre for c in self.gestor.obtener_categorias()]
        dialogo = DialogoCuenta(
            self.parent, titulo="Editar cuenta",
            servicio=cuenta.servicio, usuario=cuenta.usuario,
            categoria=cuenta.categoria, notas=cuenta.notas,
            categorias=categorias,
        )
        if dialogo.resultado:
            servicio, usuario, password, categoria, notas = dialogo.resultado
            try:
                self.gestor.actualizar(
                    cuenta_id, servicio=servicio, usuario=usuario,
                    password=password if password else None,
                    categoria=categoria, notas=notas,
                )
                self._cargar_tabla()
                messagebox.showinfo("Éxito", "Cuenta actualizada correctamente.")
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo actualizar: {e}")

    def _eliminar_cuenta(self):
        cuenta_id = self._obtener_seleccionada()
        if not cuenta_id:
            return
        if messagebox.askyesno("Confirmar", "¿Eliminar esta cuenta permanentemente?"):
            if self.gestor.eliminar(cuenta_id):
                self._cargar_tabla()
                self._actualizar_detalle()
                messagebox.showinfo("Éxito", "Cuenta eliminada.")

    def _ver_password(self):
        cuenta_id = self._obtener_seleccionada()
        if not cuenta_id:
            return
        try:
            password = self.gestor.obtener_password(cuenta_id)
            cuenta = self.gestor.obtener_cuenta(cuenta_id)
            puntaje, nivel, sugerencias = calcular_fortaleza(password)

            mensaje = (
                f"Servicio: {cuenta.servicio}\n"
                f"Usuario: {cuenta.usuario}\n"
                f"Contraseña: {password}\n"
                f"Fortaleza: {nivel} ({puntaje}/100)\n"
                f"Categoría: {cuenta.categoria}"
            )
            if cuenta.notas:
                mensaje += f"\nNotas: {cuenta.notas}"

            messagebox.showinfo("Contraseña", mensaje)
            self._actualizar_detalle(cuenta_id)

            if puntaje < 40:
                if messagebox.askyesno(
                    "Contraseña débil",
                    "Esta contraseña es débil. ¿Generar una nueva?",
                ):
                    self._editar_cuenta()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _copiar_password(self):
        cuenta_id = self._obtener_seleccionada()
        if not cuenta_id:
            return
        try:
            password = self.gestor.obtener_password(cuenta_id)
            copiar_al_portapapeles(password)
            self.gestor.registrar_auditoria(
                "password_copiado",
                f"Cuenta: {cuenta_id[:8]}..."
            )
            messagebox.showinfo(
                "Copiado",
                "Contraseña copiada al portapapeles.\nSe limpiará automáticamente en 30 segundos."
            )
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _agregar_categoria_dialogo(self):
        nombre = simpledialog.askstring("Nueva categoría", "Nombre de la categoría:")
        if nombre:
            nombre = sanitizar_entrada(nombre)
            if nombre:
                color = colorchooser.askcolor(
                    title=f"Color para '{nombre}'", initialcolor="#89b4fa"
                )[1] or "#89b4fa"
                self.gestor.agregar_categoria(nombre, color)
                self._actualizar_categorias()

    def _ver_historial(self):
        cuenta_id = self._obtener_seleccionada()
        if not cuenta_id:
            return
        historial = self.gestor.obtener_historial(cuenta_id)
        if not historial:
            messagebox.showinfo("Historial", "Sin cambios registrados.")
            return
        ventana = tk.Toplevel(self.parent)
        ventana.title("Historial de cambios")
        ventana.geometry("600x400")
        ventana.configure(bg=self._tema["bg"])
        texto = tk.Text(
            ventana, wrap=tk.WORD,
            bg=self._tema["card"], fg=self._tema["fg"],
            font=("Consolas", 9),
        )
        texto.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        for h in historial:
            texto.insert(
                tk.END,
                f"[{h.fecha[:19]}] {h.accion.upper()}"
                + (f" - {h.detalle}" if h.detalle else "")
                + "\n",
            )
        texto.config(state=tk.DISABLED)

    def _mostrar_auditoria(self):
        auditoria = self.gestor.obtener_auditoria(100)
        ventana = tk.Toplevel(self.parent)
        ventana.title("Registro de auditoría")
        ventana.geometry("700x500")
        ventana.configure(bg=self._tema["bg"])
        texto = tk.Text(
            ventana, wrap=tk.WORD,
            bg=self._tema["card"], fg=self._tema["fg"],
            font=("Consolas", 9),
        )
        texto.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        for a in auditoria:
            texto.insert(
                tk.END,
                f"[{a.fecha[:19]}] {a.evento}"
                + (f" - {a.detalle}" if a.detalle else "")
                + "\n",
            )
        texto.config(state=tk.DISABLED)

    def _mostrar_estadisticas(self):
        stats = self.gestor.obtener_estadisticas()
        mensaje = (
            f"Total de cuentas: {stats['total']}\n"
            f"Contraseñas expiradas (>90 días): {stats['expiradas']}\n\n"
            "Por categoría:\n"
        )
        for cat, cnt in stats["categorias"].items():
            mensaje += f"  • {cat}: {cnt}\n"

        debiles = self.gestor.obtener_contrasenas_debiles()
        if debiles:
            mensaje += f"\n⚠️ Contraseñas débiles: {len(debiles)}\n"
            for c, nivel, _ in debiles[:5]:
                mensaje += f"  • {c.servicio} ({nivel})\n"

        messagebox.showinfo("Estadísticas", mensaje)

    def _verificar_expiracion_al_inicio(self):
        expiradas = self.gestor.verificar_expiracion(DIAS_EXPIRACION)
        if expiradas:
            nombres = "\n".join(f"  • {c.servicio} ({c.dias_antiguedad} días)"
                               for c in expiradas[:10])
            resto = f"\n  ... y {len(expiradas) - 10} más" if len(expiradas) > 10 else ""
            messagebox.showwarning(
                "🔔 Contraseñas expiradas",
                f"{len(expiradas)} contraseña(s) tiene(n) más de {DIAS_EXPIRACION} días "
                f"sin cambiarse:\n{nombres}{resto}"
            )

    def _verificar_contrasenas_debiles(self):
        debiles = self.gestor.obtener_contrasenas_debiles()
        if debiles:
            nombres = "\n".join(f"  • {c.servicio} ({nivel})"
                               for c, nivel, _ in debiles[:5])
            resto = f"\n  ... y {len(debiles) - 5} más" if len(debiles) > 5 else ""
            messagebox.showwarning(
                "⚠️ Contraseñas débiles",
                f"Se detectaron {len(debiles)} contraseña(s) débil(es):\n"
                f"{nombres}{resto}\n\nConsidere actualizarlas."
            )

    def _exportar_vault(self):
        try:
            archivo = self.gestor.exportar_vault()
            if archivo:
                messagebox.showinfo(
                    "Exportado", f"Vault exportado a:\n{archivo}"
                )
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo exportar: {e}")

    def _importar_vault(self):
        if not messagebox.askyesno(
            "Importar",
            "Esto reemplazará TODOS los datos actuales. ¿Continuar?"
        ):
            return
        try:
            if self.gestor.importar_vault():
                self._cargar_tabla()
                messagebox.showinfo("Importado", "Vault importado correctamente.")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo importar: {e}")


class DialogoCuenta(simpledialog.Dialog):
    def __init__(
        self,
        parent,
        titulo="Cuenta",
        servicio="",
        usuario="",
        categoria="General",
        notas="",
        categorias=None,
    ):
        self.val_servicio = servicio
        self.val_usuario = usuario
        self.val_password = ""
        self.val_categoria = categoria
        self.val_notas = notas
        self._categorias = categorias or ["General"]
        self.generar_auto = False
        self.resultado = None
        super().__init__(parent, titulo)

    def body(self, frame):
        frame.configure(padx=10, pady=10)
        ttk.Label(frame, text="Servicio:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.entry_servicio = ttk.Entry(frame, width=40)
        self.entry_servicio.grid(row=0, column=1, padx=5, pady=5)
        self.entry_servicio.insert(0, self.val_servicio)

        ttk.Label(frame, text="Usuario:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.entry_usuario = ttk.Entry(frame, width=40)
        self.entry_usuario.grid(row=1, column=1, padx=5, pady=5)
        self.entry_usuario.insert(0, self.val_usuario)

        ttk.Label(frame, text="Contraseña:").grid(row=2, column=0, sticky=tk.W, pady=5)
        frame_pass = ttk.Frame(frame)
        frame_pass.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        self.entry_password = ttk.Entry(frame_pass, width=25, show="*")
        self.entry_password.pack(side=tk.LEFT)
        self.entry_password.insert(0, self.val_password)
        ttk.Button(
            frame_pass, text="Generar", command=self._generar_password
        ).pack(side=tk.LEFT, padx=(5, 0))
        self._lbl_fortaleza = tk.Label(frame_pass, text="", font=("Segoe UI", 8))
        self._lbl_fortaleza.pack(side=tk.LEFT, padx=(5, 0))
        self.entry_password.bind("<KeyRelease>", self._actualizar_fortaleza)

        ttk.Label(frame, text="Categoría:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.combo_categoria = ttk.Combobox(
            frame, values=self._categorias, state="readonly", width=37
        )
        self.combo_categoria.grid(row=3, column=1, padx=5, pady=5)
        self.combo_categoria.set(self.val_categoria if self.val_categoria in self._categorias else "General")

        ttk.Label(frame, text="Notas:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.text_notas = ScrolledText(frame, width=40, height=4)
        self.text_notas.grid(row=4, column=1, padx=5, pady=5)
        self.text_notas.insert(tk.END, self.val_notas)

        return self.entry_servicio

    def _generar_password(self):
        opciones = DialogoGenerar(self, title="Generar contraseña")
        if opciones.resultado:
            password, self.generar_auto = opciones.resultado, True
            self.entry_password.config(show="")
            self.entry_password.delete(0, tk.END)
            self.entry_password.insert(0, password)
            self._actualizar_fortaleza()

    def _actualizar_fortaleza(self, event=None):
        password = self.entry_password.get()
        if not password:
            self._lbl_fortaleza.config(text="")
            return
        puntaje, nivel, _ = calcular_fortaleza(password)
        colores = {"Muy débil": "#dc3545", "Débil": "#fd7e14",
                   "Media": "#ffc107", "Fuerte": "#198754", "Muy fuerte": "#0d6efd"}
        self._lbl_fortaleza.config(
            text=f"{nivel} ({puntaje}/100)",
            foreground=colores.get(nivel, "#6c757d"),
        )

    def apply(self):
        self.val_servicio = sanitizar_entrada(self.entry_servicio.get())
        self.val_usuario = sanitizar_entrada(self.entry_usuario.get())
        self.val_password = self.entry_password.get()
        self.val_categoria = self.combo_categoria.get()
        self.val_notas = self.text_notas.get("1.0", tk.END).strip()

        if not self.val_categoria:
            self.val_categoria = "General"

        valido, msg = validar_servicio(self.val_servicio)
        if not valido:
            messagebox.showerror("Error", msg, parent=self)
            self.resultado = None
            return

        valido, msg = validar_usuario(self.val_usuario)
        if not valido:
            messagebox.showerror("Error", msg, parent=self)
            self.resultado = None
            return

        if not self.generar_auto:
            valido, msg = validar_contrasena(self.val_password)
            if not valido:
                messagebox.showerror("Error", msg, parent=self)
                self.resultado = None
                return

        self.resultado = (
            self.val_servicio, self.val_usuario, self.val_password,
            self.val_categoria, self.val_notas,
        )


class DialogoGenerar(simpledialog.Dialog):
    def __init__(self, parent, title="Generar contraseña"):
        self.longitud = 20
        self.mayusculas = True
        self.digitos = True
        self.especiales = True
        self.ambiguos = False
        self.resultado = None
        super().__init__(parent, title)

    def body(self, frame):
        frame.configure(padx=15, pady=10)

        ttk.Label(frame, text="Longitud:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.spin_longitud = ttk.Spinbox(frame, from_=8, to=64, width=5)
        self.spin_longitud.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        self.spin_longitud.set(self.longitud)

        self.var_mayus = tk.BooleanVar(value=self.mayusculas)
        ttk.Checkbutton(frame, text="Mayúsculas", variable=self.var_mayus).grid(
            row=1, column=0, columnspan=2, sticky=tk.W, pady=2
        )
        self.var_dig = tk.BooleanVar(value=self.digitos)
        ttk.Checkbutton(frame, text="Dígitos", variable=self.var_dig).grid(
            row=2, column=0, columnspan=2, sticky=tk.W, pady=2
        )
        self.var_esp = tk.BooleanVar(value=self.especiales)
        ttk.Checkbutton(frame, text="Símbolos", variable=self.var_esp).grid(
            row=3, column=0, columnspan=2, sticky=tk.W, pady=2
        )
        self.var_amb = tk.BooleanVar(value=self.ambiguos)
        ttk.Checkbutton(frame, text="Evitar ambiguos (l1Io0O)", variable=self.var_amb).grid(
            row=4, column=0, columnspan=2, sticky=tk.W, pady=2
        )

        self._lbl_preview = tk.Label(frame, text="", font=("Consolas", 10))
        self._lbl_preview.grid(row=5, column=0, columnspan=2, pady=10)
        self._actualizar_preview()

        for child in frame.winfo_children():
            if isinstance(child, ttk.Checkbutton):
                child.configure(command=self._actualizar_preview)
        self.spin_longitud.configure(command=self._actualizar_preview)

    def _actualizar_preview(self):
        try:
            self.longitud = int(self.spin_longitud.get())
        except ValueError:
            self.longitud = 20
        password = generar_contrasena_segura(
            self.longitud, self.var_mayus.get(),
            self.var_dig.get(), self.var_esp.get(), self.var_amb.get(),
        )
        self._lbl_preview.config(text=password)

    def apply(self):
        try:
            self.longitud = int(self.spin_longitud.get())
        except ValueError:
            self.longitud = 20
        self.mayusculas = self.var_mayus.get()
        self.digitos = self.var_dig.get()
        self.especiales = self.var_esp.get()
        self.ambiguos = self.var_amb.get()
        self.resultado = generar_contrasena_segura(
            self.longitud, self.mayusculas, self.digitos,
            self.especiales, self.ambiguos,
        )
