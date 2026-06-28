import unittest
import tempfile
from pathlib import Path


from src.core.seguridad import (
    cifrar,
    descifrar,
    hash_password,
    verificar_password,
    generar_salt,
    generar_contrasena_segura,
    derivar_clave,
    cifrar_bytes,
    descifrar_bytes,
    calcular_fortaleza,
)
from src.data.modelos import Cuenta, HistorialEntry, AuditoriaEntry, Categoria
from src.data.persistencia import (
    crear_vault,
    guardar_vault,
    cargar_vault,
    verificar_clave_maestra,
    ARCHIVO_VAULT,
    ARCHIVO_SALT,
    vault_existe,
    BaseDatos,
)
from src.core.gestor import GestorContrasenas
from src.utils.helpers import (
    copiar_al_portapapeles,
    limpiar_portapapeles,
    sanitizar_entrada,
    validar_contrasena_maestra,
    validar_servicio,
)


class TestSeguridad(unittest.TestCase):
    def setUp(self):
        self.clave_maestra = "MiClaveSegura123!"
        self.texto = "Esta es una contraseña secreta"
        self.salt = generar_salt()

    def test_cifrar_descifrar(self):
        cifrado = cifrar(self.texto, self.clave_maestra, self.salt)
        self.assertIsNotNone(cifrado)
        self.assertNotEqual(cifrado, self.texto)

        descifrado = descifrar(cifrado, self.clave_maestra, self.salt)
        self.assertEqual(descifrado, self.texto)

    def test_cifrar_con_clave_incorrecta(self):
        cifrado = cifrar(self.texto, self.clave_maestra, self.salt)
        with self.assertRaises(Exception):
            descifrar(cifrado, "ClaveIncorrecta", self.salt)

    def test_hash_password(self):
        salt, hash_bytes = hash_password(self.clave_maestra)
        self.assertTrue(verificar_password(self.clave_maestra, salt, hash_bytes))
        self.assertFalse(verificar_password("OtraClave", salt, hash_bytes))

    def test_derivar_clave(self):
        clave1 = derivar_clave(self.clave_maestra, self.salt)
        clave2 = derivar_clave(self.clave_maestra, self.salt)
        clave3 = derivar_clave(self.clave_maestra, generar_salt())
        self.assertEqual(clave1, clave2)
        self.assertNotEqual(clave1, clave3)

    def test_generar_contrasena(self):
        password = generar_contrasena_segura(20)
        self.assertEqual(len(password), 20)
        password2 = generar_contrasena_segura(16, True, True, True, True)
        self.assertEqual(len(password2), 16)

    def test_salt_unico(self):
        salt1 = generar_salt()
        salt2 = generar_salt()
        self.assertNotEqual(salt1, salt2)

    def test_cifrar_descifrar_bytes(self):
        datos = b"datos binarios de prueba"
        cifrado = cifrar_bytes(datos, self.clave_maestra, self.salt)
        descifrado = descifrar_bytes(cifrado, self.clave_maestra, self.salt)
        self.assertEqual(datos, descifrado)

    def test_calcular_fortaleza(self):
        puntaje, nivel, sugerencias = calcular_fortaleza("abc")
        self.assertLess(puntaje, 30)
        self.assertIn("débil", nivel.lower())

        puntaje2, nivel2, _ = calcular_fortaleza("Str0ng!P@ssw0rd#2024")
        self.assertGreaterEqual(puntaje2, 60)
        self.assertIn("fuerte", nivel2.lower())


class TestModelos(unittest.TestCase):
    def test_cuenta_to_dict_from_dict(self):
        cuenta = Cuenta(
            servicio="GitHub",
            usuario="usuario@test.com",
            password_cifrada="encrypted_data",
            categoria="Correo",
            notas="Nota de prueba",
        )
        datos = cuenta.to_dict()
        self.assertEqual(datos["servicio"], "GitHub")
        self.assertEqual(datos["categoria"], "Correo")
        self.assertIn("id", datos)

        restaurada = Cuenta.from_dict(datos)
        self.assertEqual(restaurada.servicio, cuenta.servicio)
        self.assertEqual(restaurada.categoria, cuenta.categoria)

    def test_dias_antiguedad(self):
        from datetime import datetime, timezone, timedelta
        cuenta_vieja = Cuenta(
            servicio="Viejo", usuario="u", password_cifrada="e",
            fecha_modificacion=(datetime.now(timezone.utc) - timedelta(days=100)).isoformat(),
        )
        self.assertGreaterEqual(cuenta_vieja.dias_antiguedad, 100)

    def test_historial_entry(self):
        entry = HistorialEntry(cuenta_id="abc", accion="creada", detalle="test")
        self.assertEqual(entry.accion, "creada")
        self.assertIn("id", entry.to_dict())

    def test_auditoria_entry(self):
        entry = AuditoriaEntry(evento="login", detalle="success")
        self.assertEqual(entry.evento, "login")

    def test_categoria(self):
        cat = Categoria(nombre="Test", color="#ff0000")
        self.assertEqual(cat.to_dict()["color"], "#ff0000")


class TestPersistencia(unittest.TestCase):
    def setUp(self):
        self.clave_maestra = "MiClaveSegura123!"
        self.temp_dir = tempfile.mkdtemp()
        self.original_vault = ARCHIVO_VAULT
        self.original_salt = ARCHIVO_SALT
        self.test_vault = Path(self.temp_dir) / "vault_test.enc"
        self.test_salt = Path(self.temp_dir) / "vault_test.salt"
        import src.data.persistencia as p
        p.ARCHIVO_VAULT = self.test_vault
        p.ARCHIVO_SALT = self.test_salt
        import src.data.persistencia as p2
        p2.ARCHIVO_VAULT = self.test_vault
        p2.ARCHIVO_SALT = self.test_salt

    def tearDown(self):
        import src.data.persistencia as p
        p.ARCHIVO_VAULT = self.original_vault
        p.ARCHIVO_SALT = self.original_salt
        for f in [self.test_vault, self.test_salt]:
            if f.exists():
                f.unlink()
        if self.test_vault.parent.exists():
            self.test_vault.parent.rmdir()

    def test_crear_y_cargar_vault(self):
        salt, datos_db = crear_vault(self.clave_maestra)
        self.assertIsNotNone(salt)
        self.assertIsNotNone(datos_db)

        import sqlite3
        conn = sqlite3.connect(":memory:")
        conn.deserialize(datos_db)
        bd = BaseDatos(conn)
        self.assertEqual(len(bd.obtener_todas_cuentas()), 0)
        conn.close()

    def test_guardar_cargar_vault(self):
        salt, datos_db = crear_vault(self.clave_maestra)
        import sqlite3
        conn = sqlite3.connect(":memory:")
        conn.deserialize(datos_db)
        bd = BaseDatos(conn)
        cuenta = Cuenta(servicio="Test", usuario="u", password_cifrada="enc")
        bd.agregar_cuenta(cuenta)

        guardar_vault(conn, self.clave_maestra, salt)
        conn.close()

        self.assertTrue(self.test_vault.exists())

        conn2, salt2 = cargar_vault(self.clave_maestra)
        bd2 = BaseDatos(conn2)
        cuentas = bd2.obtener_todas_cuentas()
        self.assertEqual(len(cuentas), 1)
        self.assertEqual(cuentas[0].servicio, "Test")
        conn2.close()

    def test_verificar_clave_correcta(self):
        salt, datos_db = crear_vault(self.clave_maestra)
        import sqlite3
        conn = sqlite3.connect(":memory:")
        conn.deserialize(datos_db)
        guardar_vault(conn, self.clave_maestra, salt)
        conn.close()

        self.assertTrue(verificar_clave_maestra(self.clave_maestra))
        self.assertFalse(verificar_clave_maestra("ClaveIncorrecta"))


class TestGestor(unittest.TestCase):
    def setUp(self):
        self.clave_maestra = "MiClaveSegura123!"
        self.temp_dir = tempfile.mkdtemp()
        self.original_vault = ARCHIVO_VAULT
        self.original_salt = ARCHIVO_SALT
        self.test_vault = Path(self.temp_dir) / "vault_test.enc"
        self.test_salt = Path(self.temp_dir) / "vault_test.salt"
        import src.data.persistencia as p
        p.ARCHIVO_VAULT = self.test_vault
        p.ARCHIVO_SALT = self.test_salt
        import src.data.persistencia as p2
        p2.ARCHIVO_VAULT = self.test_vault
        p2.ARCHIVO_SALT = self.test_salt
        self.gestor = GestorContrasenas(self.clave_maestra)

    def tearDown(self):
        try:
            self.gestor.cerrar()
        except Exception:
            pass
        import src.data.persistencia as p
        p.ARCHIVO_VAULT = self.original_vault
        p.ARCHIVO_SALT = self.original_salt
        for f in [self.test_vault, self.test_salt]:
            if f.exists():
                f.unlink()
        if self.test_vault.parent.exists():
            self.test_vault.parent.rmdir()

    def test_agregar_y_obtener_cuenta(self):
        self.gestor.agregar("GitHub", "usuario@test.com", "pass123")
        cuentas = self.gestor.obtener_todas()
        self.assertEqual(len(cuentas), 1)
        self.assertEqual(cuentas[0].servicio, "GitHub")

    def test_agregar_con_categoria(self):
        self.gestor.agregar("Test", "user", "pass", categoria="Banca")
        cuentas = self.gestor.obtener_todas()
        self.assertEqual(cuentas[0].categoria, "Banca")

    def test_obtener_password_descifrado(self):
        cuenta = self.gestor.agregar("Test", "user", "MiPasswordSecreto")
        password = self.gestor.obtener_password(cuenta.id)
        self.assertEqual(password, "MiPasswordSecreto")

    def test_eliminar_cuenta(self):
        c1 = self.gestor.agregar("S1", "u1", "p1")
        c2 = self.gestor.agregar("S2", "u2", "p2")
        self.assertEqual(len(self.gestor.obtener_todas()), 2)
        self.gestor.eliminar(c1.id)
        self.assertEqual(len(self.gestor.obtener_todas()), 1)

    def test_buscar(self):
        self.gestor.agregar("GitHub", "user1@test.com", "p1")
        self.gestor.agregar("GMail", "user2@test.com", "p2")
        self.gestor.agregar("Netflix", "user3@test.com", "p3")
        resultados = self.gestor.buscar("git")
        self.assertEqual(len(resultados), 1)
        self.assertEqual(resultados[0].servicio, "GitHub")

    def test_generar_y_agregar(self):
        cuenta, password = self.gestor.generar_y_agregar("NuevoServicio", "usuario")
        self.assertIsNotNone(password)
        self.assertEqual(len(password), 20)
        recuperada = self.gestor.obtener_password(cuenta.id)
        self.assertEqual(recuperada, password)

    def test_actualizar_cuenta(self):
        cuenta = self.gestor.agregar("Original", "user", "pass")
        self.gestor.actualizar(cuenta.id, servicio="Actualizado")
        cuentas = self.gestor.obtener_todas()
        self.assertEqual(cuentas[0].servicio, "Actualizado")

    def test_categorias(self):
        self.gestor.agregar_categoria("TestCat", "#ff0000")
        cats = self.gestor.obtener_categorias()
        nombres = [c.nombre for c in cats]
        self.assertIn("TestCat", nombres)

    def test_filtrar_por_categoria(self):
        self.gestor.agregar("GitHub", "u1", "p1", categoria="Correo")
        self.gestor.agregar("Netflix", "u2", "p2", categoria="Entretenimiento")
        resultados = self.gestor.filtrar_por_categoria("Correo")
        self.assertEqual(len(resultados), 1)
        self.assertEqual(resultados[0].servicio, "GitHub")

    def test_historial(self):
        cuenta = self.gestor.agregar("Test", "u", "p")
        historial = self.gestor.obtener_historial(cuenta.id)
        self.assertTrue(len(historial) >= 1)
        self.assertEqual(historial[0].accion, "creada")

    def test_auditoria(self):
        self.gestor.agregar("Test", "u", "p")
        auditoria = self.gestor.obtener_auditoria()
        self.assertTrue(len(auditoria) >= 1)

    def test_expiracion(self):
        self.gestor.agregar("Reciente", "u", "p")
        expiradas = self.gestor.verificar_expiracion(dias_max=0)
        self.assertTrue(len(expiradas) >= 1)

    def test_contrasenas_debiles(self):
        self.gestor.agregar("Debil", "u", "1234")
        debiles = self.gestor.obtener_contrasenas_debiles()
        self.assertTrue(len(debiles) >= 1)

    def test_estadisticas(self):
        self.gestor.agregar("Test", "u", "p")
        stats = self.gestor.obtener_estadisticas()
        self.assertIn("total", stats)
        self.assertGreaterEqual(stats["total"], 1)

    def test_persistencia_entre_gestores(self):
        self.gestor.agregar("Persistente", "user", "password123")
        self.gestor.cerrar()
        gestor2 = GestorContrasenas(self.clave_maestra)
        cuentas = gestor2.obtener_todas()
        self.assertEqual(len(cuentas), 1)
        self.assertEqual(cuentas[0].servicio, "Persistente")
        gestor2.cerrar()


class TestHelpers(unittest.TestCase):
    def test_sanitizar(self):
        self.assertEqual(sanitizar_entrada("  hola  "), "hola")

    def test_validar_clave_maestra(self):
        valido, msg = validar_contrasena_maestra("1234567")
        self.assertFalse(valido)
        valido, msg = validar_contrasena_maestra("12345678")
        self.assertTrue(valido)

    def test_validar_servicio(self):
        valido, msg = validar_servicio("")
        self.assertFalse(valido)
        valido, msg = validar_servicio("GitHub")
        self.assertTrue(valido)

    def test_copiar_limpiar_portapapeles(self):
        try:
            copiar_al_portapapeles("test_password", temporizador=0)
            limpiar_portapapeles()
        except Exception:
            pass


if __name__ == "__main__":
    unittest.main()
