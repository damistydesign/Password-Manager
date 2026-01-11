import sqlite3
import os
import base64
import hashlib
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import click

class PasswordManager:
    def __init__(self, db_name='passwords.db'):
        self.db_name = db_name
        self.conn = None
        self.cursor = None
        self.key = None
        self.cipher = None
        
    def init_db(self):
        """Inicializar la base de datos"""
        self.conn = sqlite3.connect(self.db_name)
        self.cursor = self.conn.cursor()
        
        # Crear tabla para almacenar contraseñas
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service TEXT NOT NULL,
                username TEXT NOT NULL,
                encrypted_password TEXT NOT NULL,
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Crear tabla para la configuración
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        ''')
        
        self.conn.commit()
        click.echo(f"Base de datos '{self.db_name}' inicializada correctamente.")
    
    def derive_key(self, master_password, salt=None):
        """Derivar clave AES-256 desde la contraseña maestra"""
        if salt is None:
            salt = os.urandom(16)
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        return key, salt
    
    def setup_master_password(self, master_password):
        """Configurar contraseña maestra inicial"""
        salt = os.urandom(16)
        key, salt = self.derive_key(master_password, salt)
        
        # Guardar salt en la base de datos
        self.cursor.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
            ('salt', base64.b64encode(salt).decode())
        )
        
        # Verificar que podemos cifrar/descifrar
        test_data = "test"
        cipher = Fernet(key)
        encrypted = cipher.encrypt(test_data.encode())
        decrypted = cipher.decrypt(encrypted)
        
        if decrypted.decode() == test_data:
            self.conn.commit()
            return True
        return False
    
    def load_master_password(self, master_password):
        """Cargar y verificar contraseña maestra"""
        # Obtener salt de la base de datos
        self.cursor.execute("SELECT value FROM config WHERE key = 'salt'")
        result = self.cursor.fetchone()
        
        if not result:
            raise Exception("No se ha configurado una contraseña maestra. Use 'init' primero.")
        
        salt = base64.b64decode(result[0])
        key, _ = self.derive_key(master_password, salt)
        
        # Verificar que la clave funciona
        self.cipher = Fernet(key)
        
        # Prueba simple de cifrado/descifrado
        try:
            test_data = "verification"
            encrypted = self.cipher.encrypt(test_data.encode())
            self.cipher.decrypt(encrypted)
            self.key = key
            return True
        except:
            return False
    
    def encrypt_password(self, password):
        """Cifrar una contraseña"""
        if not self.cipher:
            raise Exception("No se ha cargado la contraseña maestra")
        return self.cipher.encrypt(password.encode()).decode()
    
    def decrypt_password(self, encrypted_password):
        """Descifrar una contraseña"""
        if not self.cipher:
            raise Exception("No se ha cargado la contraseña maestra")
        return self.cipher.decrypt(encrypted_password.encode()).decode()
    
    def add_password(self, service, username, password, notes=""):
        """Añadir una nueva contraseña"""
        encrypted_password = self.encrypt_password(password)
        
        self.cursor.execute(
            '''INSERT INTO passwords (service, username, encrypted_password, notes)
               VALUES (?, ?, ?, ?)''',
            (service, username, encrypted_password, notes)
        )
        self.conn.commit()
        click.echo(f"✓ Contraseña para '{service}' añadida correctamente.")
    
    def get_password(self, service, username=None):
        """Obtener una contraseña"""
        if username:
            self.cursor.execute(
                '''SELECT service, username, encrypted_password, notes 
                   FROM passwords WHERE service = ? AND username = ?''',
                (service, username)
            )
        else:
            self.cursor.execute(
                '''SELECT service, username, encrypted_password, notes 
                   FROM passwords WHERE service = ?''',
                (service,)
            )
        
        results = self.cursor.fetchall()
        return results
    
    def list_services(self):
        """Listar todos los servicios almacenados"""
        self.cursor.execute(
            "SELECT service, username, created_at FROM passwords ORDER BY service"
        )
        return self.cursor.fetchall()
    
    def update_password(self, service, username, new_password, new_notes=None):
        """Actualizar una contraseña existente"""
        encrypted_password = self.encrypt_password(new_password)
        
        if new_notes:
            self.cursor.execute(
                '''UPDATE passwords 
                   SET encrypted_password = ?, notes = ?, updated_at = CURRENT_TIMESTAMP
                   WHERE service = ? AND username = ?''',
                (encrypted_password, new_notes, service, username)
            )
        else:
            self.cursor.execute(
                '''UPDATE passwords 
                   SET encrypted_password = ?, updated_at = CURRENT_TIMESTAMP
                   WHERE service = ? AND username = ?''',
                (encrypted_password, service, username)
            )
        
        self.conn.commit()
        return self.cursor.rowcount > 0
    
    def delete_password(self, service, username):
        """Eliminar una contraseña"""
        self.cursor.execute(
            "DELETE FROM passwords WHERE service = ? AND username = ?",
            (service, username)
        )
        self.conn.commit()
        return self.cursor.rowcount > 0
    
    def search_passwords(self, search_term):
        """Buscar contraseñas por término"""
        self.cursor.execute(
            '''SELECT service, username, encrypted_password, notes 
               FROM passwords 
               WHERE service LIKE ? OR username LIKE ? OR notes LIKE ?''',
            (f'%{search_term}%', f'%{search_term}%', f'%{search_term}%')
        )
        return self.cursor.fetchall()
    
    def close(self):
        """Cerrar conexión a la base de datos"""
        if self.conn:
            self.conn.close()

@click.group()
@click.pass_context
def cli(ctx):
    """Gestor de Contraseñas CLI - Almacenamiento seguro con AES-256"""
    ctx.ensure_object(dict)
    manager = PasswordManager()
    manager.init_db()
    ctx.obj['manager'] = manager

@cli.command()
@click.pass_context
def init(ctx):
    """Inicializar con una nueva contraseña maestra"""
    manager = ctx.obj['manager']
    
    click.echo("=== Configuración de Contraseña Maestra ===")
    click.echo("Esta contraseña será usada para cifrar/descifrar todas tus contraseñas.")
    click.echo("¡Guárdala en un lugar seguro! Si la pierdes, no podrás recuperar tus datos.\n")
    
    while True:
        master_pwd = getpass("Nueva contraseña maestra: ")
        confirm_pwd = getpass("Confirmar contraseña maestra: ")
        
        if master_pwd == confirm_pwd:
            if len(master_pwd) < 8:
                click.echo("❌ La contraseña debe tener al menos 8 caracteres.")
                continue
            
            try:
                if manager.setup_master_password(master_pwd):
                    click.echo("✅ Contraseña maestra configurada correctamente.")
                    break
                else:
                    click.echo("❌ Error al configurar la contraseña maestra.")
            except Exception as e:
                click.echo(f"❌ Error: {str(e)}")
        else:
            click.echo("❌ Las contraseñas no coinciden.")

@cli.command()
@click.pass_context
@click.option('--service', '-s', required=True, help='Nombre del servicio (ej: Gmail)')
@click.option('--username', '-u', required=True, help='Nombre de usuario/email')
@click.option('--password', '-p', help='Contraseña (se pedirá si no se proporciona)')
@click.option('--notes', '-n', help='Notas adicionales')
def add(ctx, service, username, password, notes):
    """Añadir una nueva contraseña"""
    manager = ctx.obj['manager']
    
    # Solicitar contraseña maestra
    master_pwd = getpass("Contraseña maestra: ")
    
    try:
        if not manager.load_master_password(master_pwd):
            click.echo("❌ Contraseña maestra incorrecta.")
            return
        
        # Solicitar contraseña si no se proporcionó
        if not password:
            password = getpass(f"Contraseña para {service}: ")
            confirm = getpass("Confirmar contraseña: ")
            
            if password != confirm:
                click.echo("❌ Las contraseñas no coinciden.")
                return
        
        manager.add_password(service, username, password, notes or "")
        
    except Exception as e:
        click.echo(f"❌ Error: {str(e)}")

@cli.command()
@click.pass_context
@click.option('--service', '-s', required=True, help='Servicio a buscar')
@click.option('--username', '-u', help='Usuario específico (opcional)')
@click.option('--show', is_flag=True, help='Mostrar la contraseña en texto claro')
def get(ctx, service, username, show):
    """Obtener una contraseña almacenada"""
    manager = ctx.obj['manager']
    
    master_pwd = getpass("Contraseña maestra: ")
    
    try:
        if not manager.load_master_password(master_pwd):
            click.echo("❌ Contraseña maestra incorrecta.")
            return
        
        results = manager.get_password(service, username)
        
        if not results:
            click.echo(f"❌ No se encontraron entradas para '{service}'")
            return
        
        for i, (svc, user, enc_pwd, notes) in enumerate(results, 1):
            click.echo(f"\n[{i}] Servicio: {svc}")
            click.echo(f"   Usuario: {user}")
            
            if show:
                try:
                    password = manager.decrypt_password(enc_pwd)
                    click.echo(f"   Contraseña: {password}")
                except Exception as e:
                    click.echo(f"   ❌ Error al descifrar: {str(e)}")
            else:
                click.echo(f"   Contraseña: [cifrada - usa --show para ver]")
            
            if notes:
                click.echo(f"   Notas: {notes}")
            
    except Exception as e:
        click.echo(f"❌ Error: {str(e)}")

@cli.command()
@click.pass_context
def list(ctx):
    """Listar todos los servicios almacenados"""
    manager = ctx.obj['manager']
    
    try:
        results = manager.list_services()
        
        if not results:
            click.echo("No hay contraseñas almacenadas.")
            return
        
        click.echo("\n=== Servicios Almacenados ===\n")
        for service, username, created_at in results:
            click.echo(f"• {service} - {username} (creado: {created_at[:10]})")
        click.echo(f"\nTotal: {len(results)} entradas")
        
    except Exception as e:
        click.echo(f"❌ Error: {str(e)}")

@cli.command()
@click.pass_context
@click.option('--service', '-s', required=True, help='Servicio a actualizar')
@click.option('--username', '-u', required=True, help='Usuario a actualizar')
def update(ctx, service, username):
    """Actualizar una contraseña existente"""
    manager = ctx.obj['manager']
    
    master_pwd = getpass("Contraseña maestra: ")
    
    try:
        if not manager.load_master_password(master_pwd):
            click.echo("❌ Contraseña maestra incorrecta.")
            return
        
        # Verificar que existe
        existing = manager.get_password(service, username)
        if not existing:
            click.echo(f"❌ No se encontró '{username}' en '{service}'")
            return
        
        click.echo(f"\nActualizando: {service} - {username}")
        new_password = getpass("Nueva contraseña: ")
        confirm = getpass("Confirmar nueva contraseña: ")
        
        if new_password != confirm:
            click.echo("❌ Las contraseñas no coinciden.")
            return
        
        notes = click.prompt("Notas (Enter para mantener actual)", default="", show_default=False)
        
        success = manager.update_password(
            service, 
            username, 
            new_password, 
            notes if notes != "" else None
        )
        
        if success:
            click.echo("✅ Contraseña actualizada correctamente.")
        else:
            click.echo("❌ No se pudo actualizar la contraseña.")
        
    except Exception as e:
        click.echo(f"❌ Error: {str(e)}")

@cli.command()
@click.pass_context
@click.option('--service', '-s', required=True, help='Servicio a eliminar')
@click.option('--username', '-u', required=True, help='Usuario a eliminar')
@click.confirmation_option(prompt='¿Estás seguro de que quieres eliminar esta contraseña?')
def delete(ctx, service, username):
    """Eliminar una contraseña almacenada"""
    manager = ctx.obj['manager']
    
    master_pwd = getpass("Contraseña maestra: ")
    
    try:
        if not manager.load_master_password(master_pwd):
            click.echo("❌ Contraseña maestra incorrecta.")
            return
        
        success = manager.delete_password(service, username)
        
        if success:
            click.echo(f"✅ Entrada '{username}' en '{service}' eliminada.")
        else:
            click.echo(f"❌ No se encontró '{username}' en '{service}'")
        
    except Exception as e:
        click.echo(f"❌ Error: {str(e)}")

@cli.command()
@click.pass_context
@click.option('--search', '-q', required=True, help='Término de búsqueda')
def search(ctx, search):
    """Buscar contraseñas por término"""
    manager = ctx.obj['manager']
    
    master_pwd = getpass("Contraseña maestra: ")
    
    try:
        if not manager.load_master_password(master_pwd):
            click.echo("❌ Contraseña maestra incorrecta.")
            return
        
        results = manager.search_passwords(search)
        
        if not results:
            click.echo(f"❌ No se encontraron resultados para '{search}'")
            return
        
        click.echo(f"\n=== Resultados para '{search}' ===\n")
        for i, (service, username, enc_pwd, notes) in enumerate(results, 1):
            click.echo(f"[{i}] {service} - {username}")
            if notes:
                click.echo(f"    Notas: {notes[:50]}..." if len(notes) > 50 else f"    Notas: {notes}")
        
    except Exception as e:
        click.echo(f"❌ Error: {str(e)}")

@cli.command()
@click.pass_context
def stats(ctx):
    """Mostrar estadísticas del gestor"""
    manager = ctx.obj['manager']
    
    try:
        manager.cursor.execute("SELECT COUNT(*) FROM passwords")
        total = manager.cursor.fetchone()[0]
        
        manager.cursor.execute("""
            SELECT service, COUNT(*) as count 
            FROM passwords 
            GROUP BY service 
            ORDER BY count DESC
        """)
        services = manager.cursor.fetchall()
        
        click.echo("\n=== Estadísticas ===\n")
        click.echo(f"Contraseñas almacenadas: {total}")
        
        if services:
            click.echo("\nServicios por frecuencia:")
            for service, count in services[:10]:  # Mostrar top 10
                click.echo(f"  • {service}: {count} entradas")
        
    except Exception as e:
        click.echo(f"❌ Error: {str(e)}")

if __name__ == '__main__':
    cli()