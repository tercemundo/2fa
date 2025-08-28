# Sistema de Autenticación 2FA con Streamlit

Esta es una aplicación web simple construida con Streamlit que demuestra un sistema de autenticación de usuarios completo, incluyendo registro, inicio de sesión y autenticación de dos factores (2FA) compatible con Google Authenticator y otras aplicaciones similares.

## Características

-   **Registro de Usuarios:** Creación de nuevas cuentas de usuario.
-   **Inicio de Sesión Seguro:** Autenticación de usuarios con contraseñas hasheadas.
-   **Autenticación de Dos Factores (2FA):**
    -   Generación de un secreto TOTP (Time-based One-Time Password).
    -   Visualización de un código QR para una fácil configuración con aplicaciones como Google Authenticator, Authy, etc.
    -   Verificación del código TOTP como segundo factor de autenticación.
-   **Códigos de Recuperación:** Generación de códigos de un solo uso para recuperar el acceso a la cuenta si se pierde el dispositivo 2FA.
-   **Base de Datos:** Utiliza SQLite para almacenar la información de los usuarios de forma persistente.

## Prerrequisitos

-   Python 3.7 o superior.
-   `pip` para instalar paquetes de Python.

## Instalación

1.  **Clona o descarga el repositorio:**
    Si estás usando git:
    ```bash
    git clone <url-del-repositorio>
    cd <directorio-del-repositorio>
    ```
    Si no, simplemente descarga los archivos `app.py` y `requirements.txt` en un directorio.

2.  **Crea un entorno virtual (recomendado):**
    ```bash
    python -m venv venv
    ```
    Activa el entorno:
    -   **Windows:**
        ```bash
        .\venv\Scripts\activate
        ```
    -   **macOS/Linux:**
        ```bash
        source venv/bin/activate
        ```

3.  **Instala las dependencias:**
    Ejecuta el siguiente comando para instalar las librerías necesarias a partir del archivo `requirements.txt`:
    ```bash
    pip install -r requirements.txt
    ```

## Ejecución

Una vez que hayas instalado las dependencias, puedes ejecutar la aplicación con el siguiente comando:

```bash
streamlit run app.py
```

Esto iniciará la aplicación y la abrirá en tu navegador web predeterminado.

## ¿Cómo usar la autenticación 2FA?

1.  **Regístrate:**
    -   Abre la aplicación.
    -   Ve a la pestaña "Registrarse".
    -   Ingresa un nombre de usuario y una contraseña, y confírmala.
    -   Haz clic en "Registrarse".

2.  **Inicia Sesión por Primera Vez:**
    -   Ve a la pestaña "Iniciar Sesión".
    -   Ingresa las credenciales que acabas de crear.

3.  **Habilita el 2FA:**
    -   Una vez dentro de tu panel, verás la opción para "Habilitar 2FA". Haz clic en el botón.
    -   La aplicación generará un código QR y un secreto de texto.

4.  **Configura Google Authenticator (o similar):**
    -   Abre tu aplicación de autenticación en tu teléfono (Google Authenticator, Authy, Microsoft Authenticator, etc.).
    -   Selecciona la opción para añadir una nueva cuenta.
    -   Elige "Escanear código QR" y apunta la cámara de tu teléfono al código QR que se muestra en la aplicación Streamlit.
    -   Si no puedes escanear el QR, puedes ingresar el código secreto manualmente en la aplicación de autenticación.

5.  **Guarda tus Códigos de Recuperación:**
    -   La aplicación también mostrará una lista de códigos de recuperación.
    -   **¡MUY IMPORTANTE!** Copia estos códigos y guárdalos en un lugar seguro (un gestor de contraseñas, un documento impreso, etc.). Los necesitarás si pierdes el acceso a tu teléfono.

6.  **Verifica el 2FA:**
    -   Cierra la sesión en la aplicación Streamlit.
    -   Inicia sesión de nuevo con tu usuario y contraseña.
    -   Ahora, la aplicación te pedirá un "Código de verificación".
    -   Abre Google Authenticator, busca el código de 6 dígitos para "MiApp" y escríbelo en el campo de verificación.
    -   ¡Listo! Has iniciado sesión de forma segura con 2FA.

7.  **Uso de Códigos de Recuperación:**
    -   Si alguna vez pierdes tu dispositivo de autenticación, en la pantalla de verificación 2FA, puedes ingresar uno de tus códigos de recuperación (de 8 caracteres) en lugar del código de 6 dígitos.
    -   Recuerda que cada código de recuperación solo se puede usar una vez.
