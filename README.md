# Password Manager CLI

Un gestor de contraseñas seguro en línea de comandos con cifrado AES-256.

## Características

- 🔒 Cifrado AES-256 para todas las contraseñas
- 💾 Almacenamiento local con SQLite
- 🛡️ Contraseña maestra protegida con PBKDF2
- 📝 Interfaz CLI intuitiva con Click
- 🔍 Búsqueda de contraseñas
- 📊 Estadísticas de uso

## Instalación

```bash
pip install -r requirements.txt
```

## Uso
### 1. Inicializar el gestor
```
python password_manager.py init
```
### 2. Añadir una contraseña
```
python password_manager.py add -s Gmail -u usuario@gmail.com
```
### 3. Obtener una contraseña
```
python password_manager.py get -s Gmail --show
```
### 4. Listar todas las entradas
```
python password_manager.py list
```
### 5. Actualizar una contraseña
```
python password_manager.py update -s Gmail -u usuario@gmail.com
```
### 6. Eliminar una contraseña
```
python password_manager.py delete -s Gmail -u usuario@gmail.com
```
### 7. Buscar contraseñas
```
python password_manager.py search -q "google"
```
### 8. Ver estadísticas
```
python password_manager.py stats
```
# Seguridad
- Las contraseñas se cifran con AES-256 en modo Fernet

- La clave maestra se deriva con PBKDF2-HMAC-SHA256 (100,000 iteraciones)

- Cada contraseña tiene su propio nonce (IV)

- Base de datos local, sin envío a la nube

# Advertencias
- Guarda tu contraseña maestra en un lugar seguro

- Realiza copias de seguridad del archivo passwords.db

- No compartas tu archivo de base de datos

## Estructura de la base de datos
- **Tabla `passwords`:** Almacena contraseñas cifradas

- **Tabla `config`:** Almacena salt para derivación de clave

## 6. Uso del programa

### Comandos disponibles:

### Inicializar por primera vez
```python password_manager.py init```

### Añadir una contraseña
```python password_manager.py add -s "Gmail" -u "usuario@gmail.com"```

### Ver todas las contraseñas (sin mostrar)
```python password_manager.py list```

### Obtener una contraseña específica
```python password_manager.py get -s "Gmail" --show``

### Buscar contraseñas
```python password_manager.py search -q "banco"```

### Ver ayuda general
```python password_manager.py --help```

### Ver ayuda de un comando específico
```python password_manager.py add --help```

## Características de seguridad implementadas:
- **AES-256-GCM:** Cifrado autenticado

- **PBKDF2:** Deriva clave de 256 bits desde la contraseña maestra

- **Salt único:** Diferente para cada instalación

- **100,000 iteraciones:** Para hacer ataques por fuerza bruta más difíciles

- **Fernet tokens:** Incluyen timestamp para prevenir replay attacks

- **Entrada protegida:** Uso de `getpass()` para no mostrar contraseñas en pantalla
