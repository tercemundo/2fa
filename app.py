import streamlit as st
import sqlite3
import hashlib
import hmac
import time
import secrets
import string
import base64
import io
import qrcode
from datetime import datetime
import struct

class AuthSystem:
    def __init__(self, db_path="auth.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Inicializar base de datos SQLite"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Crear tabla de usuarios
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                totp_secret TEXT,
                is_2fa_enabled INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Crear tabla de códigos de recuperación
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS recovery_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                code TEXT NOT NULL,
                used INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)
        
        conn.commit()
        conn.close()
    
    def hash_password(self, password):
        """Hash de contraseña usando SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def verify_password(self, password, hash_password):
        """Verificar contraseña"""
        return self.hash_password(password) == hash_password
    
    def register_user(self, username, password):
        """Registrar nuevo usuario"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            password_hash = self.hash_password(password)
            cursor.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash)
            )
            
            conn.commit()
            conn.close()
            return True
        except sqlite3.IntegrityError:
            return False
    
    def authenticate_user(self, username, password):
        """Autenticar usuario (primer factor)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT id, username, password_hash, is_2fa_enabled FROM users WHERE username = ?",
            (username,)
        )
        
        user = cursor.fetchone()
        conn.close()
        
        if user and self.verify_password(password, user[2]):
            return {
                'success': True,
                'user_id': user[0],
                'username': user[1],
                'needs_2fa': bool(user[3])
            }
        return {'success': False}
    
    def generate_totp_secret(self):
        """Generar secreto TOTP"""
        alphabet = string.ascii_uppercase + "234567"
        return ''.join(secrets.choice(alphabet) for _ in range(16))
    
    def enable_2fa(self, user_id):
        """Habilitar 2FA para un usuario"""
        secret = self.generate_totp_secret()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "UPDATE users SET totp_secret = ?, is_2fa_enabled = 1 WHERE id = ?",
            (secret, user_id)
        )
        
        # Generar códigos de recuperación
        recovery_codes = self.generate_recovery_codes(user_id, cursor)
        
        conn.commit()
        conn.close()
        
        return secret, recovery_codes
    
    def generate_recovery_codes(self, user_id, cursor):
        """Generar códigos de recuperación"""
        codes = []
        for _ in range(10):
            code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
            codes.append(code)
            cursor.execute(
                "INSERT INTO recovery_codes (user_id, code) VALUES (?, ?)",
                (user_id, code)
            )
        return codes
    
    def base32_decode(self, secret):
        """Decodificar Base32 manualmente"""
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        decoded = bytearray()
        
        # Remover espacios y convertir a mayúsculas
        secret = secret.replace(' ', '').upper()
        
        # Procesar en grupos de 8 caracteres
        for i in range(0, len(secret), 8):
            chunk = secret[i:i+8].ljust(8, '=')
            
            # Convertir cada carácter a su valor de 5 bits
            bits = ''
            for char in chunk:
                if char == '=':
                    break
                if char in alphabet:
                    bits += format(alphabet.index(char), '05b')
            
            # Convertir grupos de 8 bits a bytes
            for j in range(0, len(bits), 8):
                if j + 8 <= len(bits):
                    decoded.append(int(bits[j:j+8], 2))
        
        return bytes(decoded)
    
    def generate_totp_code(self, secret, time_step=None):
        """Generar código TOTP"""
        if time_step is None:
            time_step = int(time.time() // 30)
        
        # Decodificar el secreto
        key = self.base32_decode(secret)
        
        # Crear el contador de tiempo como bytes
        counter = struct.pack('>Q', time_step)
        
        # Generar HMAC-SHA1
        mac = hmac.new(key, counter, hashlib.sha1).digest()
        
        # Truncamiento dinámico
        offset = mac[-1] & 0x0f
        code = struct.unpack('>I', mac[offset:offset+4])[0]
        code &= 0x7fffffff
        code %= 1000000
        
        return f"{code:06d}"
    
    def verify_totp_code(self, user_id, code):
        """Verificar código TOTP"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT totp_secret FROM users WHERE id = ?", (user_id,))
        result = cursor.fetchone()
        conn.close()
        
        if not result or not result[0]:
            return False
        
        secret = result[0]
        current_time = int(time.time() // 30)
        
        # Verificar código actual y ±1 ventana de tiempo
        for time_step in [current_time - 1, current_time, current_time + 1]:
            if self.generate_totp_code(secret, time_step) == code:
                return True
        
        return False
    
    def verify_recovery_code(self, user_id, code):
        """Verificar código de recuperación"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT id FROM recovery_codes WHERE user_id = ? AND code = ? AND used = 0",
            (user_id, code.upper())
        )
        
        result = cursor.fetchone()
        if result:
            # Marcar código como usado
            cursor.execute(
                "UPDATE recovery_codes SET used = 1 WHERE id = ?",
                (result[0],)
            )
            conn.commit()
            conn.close()
            return True
        
        conn.close()
        return False
    
    def get_user_info(self, user_id):
        """Obtener información del usuario"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT id, username, is_2fa_enabled FROM users WHERE id = ?",
            (user_id,)
        )
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return {
                'id': result[0],
                'username': result[1],
                'is_2fa_enabled': bool(result[2])
            }
        return None
    
    def generate_qr_code(self, secret, username, issuer="MiApp"):
        """Generar código QR para configuración TOTP"""
        totp_uri = f"otpauth://totp/{issuer}:{username}?secret={secret}&issuer={issuer}"
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        qr_image = qr.make_image(fill_color="black", back_color="white")
        
        # Convertir a bytes para Streamlit
        img_buffer = io.BytesIO()
        qr_image.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        
        return img_buffer

# Inicializar sistema de autenticación
@st.cache_resource
def get_auth_system():
    return AuthSystem()

def init_session_state():
    """Inicializar estado de sesión"""
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    if 'user_id' not in st.session_state:
        st.session_state.user_id = None
    if 'username' not in st.session_state:
        st.session_state.username = None
    if 'needs_2fa' not in st.session_state:
        st.session_state.needs_2fa = False
    if 'pending_user_id' not in st.session_state:
        st.session_state.pending_user_id = None

def login_page():
    """Página de login"""
    st.title("🔐 Sistema de Autenticación con 2FA")
    
    tab1, tab2 = st.tabs(["Iniciar Sesión", "Registrarse"])
    
    with tab1:
        st.header("Iniciar Sesión")
        with st.form("login_form"):
            username = st.text_input("Usuario")
            password = st.text_input("Contraseña", type="password")
            submit = st.form_submit_button("Iniciar Sesión")
            
            if submit and username and password:
                auth = get_auth_system()
                result = auth.authenticate_user(username, password)
                
                if result['success']:
                    if result['needs_2fa']:
                        st.session_state.needs_2fa = True
                        st.session_state.pending_user_id = result['user_id']
                        st.session_state.username = result['username']
                        st.rerun()
                    else:
                        st.session_state.logged_in = True
                        st.session_state.user_id = result['user_id']
                        st.session_state.username = result['username']
                        st.success("¡Inicio de sesión exitoso!")
                        st.rerun()
                else:
                    st.error("Credenciales inválidas")
    
    with tab2:
        st.header("Crear Cuenta")
        with st.form("register_form"):
            new_username = st.text_input("Nuevo Usuario")
            new_password = st.text_input("Nueva Contraseña", type="password")
            confirm_password = st.text_input("Confirmar Contraseña", type="password")
            register = st.form_submit_button("Registrarse")
            
            if register and new_username and new_password:
                if new_password != confirm_password:
                    st.error("Las contraseñas no coinciden")
                elif len(new_password) < 6:
                    st.error("La contraseña debe tener al menos 6 caracteres")
                else:
                    auth = get_auth_system()
                    if auth.register_user(new_username, new_password):
                        st.success("¡Usuario creado exitosamente! Ahora puedes iniciar sesión.")
                    else:
                        st.error("El usuario ya existe")

def two_factor_page():
    """Página de verificación 2FA"""
    st.title("🛡️ Verificación en Dos Pasos")
    
    st.info("Ingresa el código de 6 dígitos de tu aplicación de autenticación o un código de recuperación.")
    
    with st.form("2fa_form"):
        code = st.text_input("Código de verificación", placeholder="123456 o código de recuperación")
        verify = st.form_submit_button("Verificar")
        
        if verify and code:
            auth = get_auth_system()
            user_id = st.session_state.pending_user_id
            
            # Intentar verificar código TOTP primero
            if len(code) == 6 and code.isdigit():
                if auth.verify_totp_code(user_id, code):
                    st.session_state.logged_in = True
                    st.session_state.user_id = user_id
                    st.session_state.needs_2fa = False
                    st.session_state.pending_user_id = None
                    st.success("¡Verificación exitosa!")
                    st.rerun()
                else:
                    st.error("Código TOTP inválido")
            
            # Intentar código de recuperación
            elif len(code) == 8:
                if auth.verify_recovery_code(user_id, code):
                    st.session_state.logged_in = True
                    st.session_state.user_id = user_id
                    st.session_state.needs_2fa = False
                    st.session_state.pending_user_id = None
                    st.success("¡Código de recuperación usado exitosamente!")
                    st.warning("Recuerda que este código de recuperación ya no se puede volver a usar.")
                    st.rerun()
                else:
                    st.error("Código de recuperación inválido")
            else:
                st.error("Formato de código inválido")
    
    if st.button("Cancelar"):
        st.session_state.needs_2fa = False
        st.session_state.pending_user_id = None
        st.rerun()

def dashboard_page():
    """Panel principal del usuario"""
    auth = get_auth_system()
    user_info = auth.get_user_info(st.session_state.user_id)
    
    st.title(f"👋 Bienvenido, {user_info['username']}!")
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        st.success("Has iniciado sesión correctamente.")
    
    with col2:
        if st.button("Cerrar Sesión"):
            # Limpiar sesión
            st.session_state.logged_in = False
            st.session_state.user_id = None
            st.session_state.username = None
            st.session_state.needs_2fa = False
            st.session_state.pending_user_id = None
            st.rerun()
    
    st.divider()
    
    # Configuración de 2FA
    if not user_info['is_2fa_enabled']:
        st.header("🔒 Configurar Autenticación en Dos Pasos")
        st.info("Para mayor seguridad, te recomendamos habilitar la autenticación en dos pasos (2FA).")
        
        if st.button("Habilitar 2FA"):
            secret, recovery_codes = auth.enable_2fa(st.session_state.user_id)
            
            st.success("¡2FA habilitado correctamente!")
            
            # Mostrar QR Code
            st.subheader("📱 Configuración")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.write("**Paso 1:** Descarga una app como Google Authenticator o Authy")
                st.write("**Paso 2:** Escanea este código QR:")
                
                qr_buffer = auth.generate_qr_code(secret, user_info['username'])
                st.image(qr_buffer, width=200)
            
            with col2:
                st.write("**O ingresa manualmente este código:**")
                st.code(secret, language=None)
                
                st.write("**Códigos de recuperación:**")
                st.warning("Guarda estos códigos en un lugar seguro. Los necesitarás si pierdes acceso a tu teléfono.")
                
                codes_text = '\n'.join(recovery_codes)
                st.text_area("Códigos de recuperación", codes_text, height=200)
            
            st.info("Una vez configurado, cierra sesión e inicia sesión nuevamente para probar el 2FA.")
    
    else:
        st.header("✅ Seguridad")
        st.success("Autenticación en dos pasos habilitada")
        
        # Información adicional
        with st.expander("ℹ️ Información de tu cuenta"):
            st.write(f"**Usuario:** {user_info['username']}")
            st.write(f"**ID:** {user_info['id']}")
            st.write(f"**2FA:** {'Habilitado' if user_info['is_2fa_enabled'] else 'Deshabilitado'}")

def main():
    """Función principal de la aplicación"""
    st.set_page_config(
        page_title="Autenticación 2FA",
        page_icon="🔐",
        layout="wide"
    )
    
    # Inicializar estado de sesión
    init_session_state()
    
    # Routing de páginas
    if not st.session_state.logged_in:
        if st.session_state.needs_2fa:
            two_factor_page()
        else:
            login_page()
    else:
        dashboard_page()

if __name__ == "__main__":
    main()
