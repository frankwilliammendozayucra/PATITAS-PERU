from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
import os
from config import obtener_conexion

app = Flask(__name__)

# Configuración de la aplicación
app.secret_key = 'clave_secreta_segura'  # Cambia por una clave más segura
bcrypt = Bcrypt(app)
app.config['UPLOAD_FOLDER'] = 'static/uploads/'
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Decorador para proteger rutas
def login_requerido(func):
    def wrapper(*args, **kwargs):
        if 'usuario_id' not in session:
            flash('Por favor, inicia sesión para acceder a esta página', 'warning')
            return redirect('/login')
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

# Ruta principal redirige al login si no hay sesión activa
@app.route('/')
@login_requerido
def index():
    return render_template('index.html', usuario_nombre=session.get('usuario_nombre'))

# Ruta para registro de usuarios
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nombre = request.form['nombre']
        email = request.form['email']
        contrasena = request.form['contrasena']
        contrasena_hash = bcrypt.generate_password_hash(contrasena).decode('utf-8')

        try:
            conexion = obtener_conexion()
            cursor = conexion.cursor()
            cursor.execute("""
                INSERT INTO usuarios (nombre, email, contrasena)
                VALUES (%s, %s, %s)
            """, (nombre, email, contrasena_hash))
            conexion.commit()
            conexion.close()

            flash('Usuario registrado exitosamente', 'success')
            return redirect('/login')
        except Exception as e:
            flash('Error al registrar el usuario. El correo ya está en uso.', 'danger')

    return render_template('register.html')

# Ruta para inicio de sesión
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        contrasena = request.form['contrasena']

        conexion = obtener_conexion()
        cursor = conexion.cursor(dictionary=True)
        cursor.execute("SELECT * FROM usuarios WHERE email = %s", (email,))
        usuario = cursor.fetchone()
        conexion.close()

        if usuario and bcrypt.check_password_hash(usuario['contrasena'], contrasena):
            session['usuario_id'] = usuario['id']
            session['usuario_nombre'] = usuario['nombre']
            flash(f'Bienvenido, {usuario["nombre"]}', 'success')
            return redirect('/')
        else:
            flash('Correo o contraseña incorrectos', 'danger')

    return render_template('login.html')

# Ruta para cerrar sesión
@app.route('/logout')
def logout():
    session.clear()
    flash('Sesión cerrada exitosamente', 'success')
    return redirect('/login')

# Ruta para subir un perro
@app.route('/subir_perro', methods=['GET', 'POST'])
@login_requerido
def subir_perro():
    if request.method == 'POST':
        nombre = request.form['nombre']
        edad = request.form['edad']
        raza = request.form['raza']
        tamano = request.form['tamano']
        descripcion = request.form['descripcion']
        imagen = request.files['imagen']
        usuario_id = session['usuario_id']  # Obtener el usuario que está creando

        if imagen:
            ruta_imagen = os.path.join(app.config['UPLOAD_FOLDER'], imagen.filename)
            imagen.save(ruta_imagen)

            conexion = obtener_conexion()
            cursor = conexion.cursor()
            cursor.execute("""
                INSERT INTO perros (nombre, edad, raza, tamano, descripcion, imagen, usuario_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (nombre, edad, raza, tamano, descripcion, ruta_imagen, usuario_id))
            conexion.commit()
            conexion.close()

        return redirect('/ver_perros')

    return render_template('subir_perro.html')

# Ruta para ver todos los perros con filtros de búsqueda
@app.route('/ver_perros', methods=['GET'])
@login_requerido
def ver_perros():
    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)

    # Filtros opcionales
    raza = request.args.get('raza')
    tamano = request.args.get('tamano')
    edad = request.args.get('edad')

    # Construir consulta dinámica
    consulta = "SELECT * FROM perros WHERE 1=1"
    parametros = []

    if raza:
        consulta += " AND raza = %s"
        parametros.append(raza)

    if tamano:
        consulta += " AND tamano = %s"
        parametros.append(tamano)

    if edad:
        consulta += " AND edad = %s"
        parametros.append(edad)

    cursor.execute(consulta, tuple(parametros))
    perros = cursor.fetchall()
    conexion.close()

    return render_template('ver_perros.html', perros=perros)

# Ruta para reportar un perro perdido
@app.route('/reportar', methods=['GET', 'POST'])
@login_requerido
def reportar():
    if request.method == 'POST':
        nombre = request.form['nombre']
        descripcion = request.form['descripcion']
        ubicacion = request.form['ubicacion']
        imagen = request.files['imagen']
        usuario_id = session['usuario_id']  # Obtener el usuario que está creando

        if imagen:
            ruta_imagen = os.path.join(app.config['UPLOAD_FOLDER'], imagen.filename)
            imagen.save(ruta_imagen)

            conexion = obtener_conexion()
            cursor = conexion.cursor()
            cursor.execute("""
                INSERT INTO reportes (nombre_perro, descripcion, ubicacion, imagen, usuario_id)
                VALUES (%s, %s, %s, %s, %s)
            """, (nombre, descripcion, ubicacion, ruta_imagen, usuario_id))
            conexion.commit()
            conexion.close()

        return redirect('/ver_reportes')

    return render_template('reportar.html')

# Ruta para ver reportes de perros perdidos con filtros de búsqueda
@app.route('/ver_reportes', methods=['GET'])
@login_requerido
def ver_reportes():
    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)

    # Filtros opcionales
    nombre_perro = request.args.get('nombre_perro')
    descripcion = request.args.get('descripcion')
    ubicacion = request.args.get('ubicacion')

    # Construir consulta dinámica
    consulta = "SELECT * FROM reportes WHERE 1=1"
    parametros = []

    if nombre_perro:
        consulta += " AND nombre_perro LIKE %s"
        parametros.append(f"%{nombre_perro}%")

    if descripcion:
        consulta += " AND descripcion LIKE %s"
        parametros.append(f"%{descripcion}%")

    if ubicacion:
        consulta += " AND ubicacion LIKE %s"
        parametros.append(f"%{ubicacion}%")

    cursor.execute(consulta, tuple(parametros))
    reportes = cursor.fetchall()
    conexion.close()

    return render_template('ver_reportes.html', reportes=reportes)

if __name__ == '__main__':
    app.run(debug=True)
