import tkinter as tk
from tkinter import messagebox
import requests
import bcrypt
import os

USER_DATA_FILE = 'usuarios.txt'
REMEMBER_ME_FILE = 'recordar.txt'


def buscar_libros(entry):
    termino_busqueda = entry.get()

    if not termino_busqueda:
        messagebox.showerror("Error", "Por favor, introduce un término de búsqueda.")
        return

    url = f"https://www.googleapis.com/books/v1/volumes?q={termino_busqueda}"

    try:
        response = requests.get(url)
        response.raise_for_status()

        data = response.json()

        ventana_resultados = tk.Toplevel()
        ventana_resultados.title("Resultados de búsqueda")
        ventana_resultados.geometry("600x400")
        ventana_resultados.resizable(False, False)

        text_resultados = tk.Text(ventana_resultados, wrap=tk.WORD, font=("Arial", 12))
        text_resultados.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        for item in data['items']:
            info_libro = item['volumeInfo']
            titulo = info_libro.get('title', 'No disponible')
            autores = ', '.join(info_libro.get('authors', ['Autor desconocido']))
            descripcion = info_libro.get('description', 'Sin descripción disponible')

            text_resultados.insert(tk.END, f"Título: {titulo}\n")
            text_resultados.insert(tk.END, f"Autor(es): {autores}\n")
            text_resultados.insert(tk.END, f"Descripción: {descripcion}\n\n")
            text_resultados.insert(tk.END, "-" * 50 + "\n\n")

    except requests.exceptions.RequestException as e:
        messagebox.showerror("Error", f"Error al realizar la solicitud a la API:\n\n {str(e)}")


def validar_acceso():
    usuario = entry_usuario.get()
    password = entry_password.get()
    recordar = var_recordar.get()

    if not usuario or not password:
        messagebox.showerror('Error', 'Por favor, complete todos los campos.')
        return

    if validar_credenciales(usuario, password):
        if recordar:
            with open(REMEMBER_ME_FILE, 'w') as f:
                f.write(f"{usuario},{password}\n")
        messagebox.showinfo('Acceso correcto', 'Bienvenido/a ' + usuario)
        abrir_selector_de_libros()
    else:
        messagebox.showerror('Acceso denegado', 'Contraseña o usuario incorrecta.')


def abrir_selector_de_libros():
    ventana_acceso.destroy()

    libros_disponibles = tk.Tk()
    libros_disponibles.title('Buscar libros')
    libros_disponibles.geometry('600x400')
    libros_disponibles.resizable(False, False)

    (tk.Label(libros_disponibles, text="Escribir Libro:", font=("Arial", 12))
     .grid(row=0, column=0, padx=10, pady=10, sticky="e"))
    entry_busqueda = tk.Entry(libros_disponibles, font=("Arial", 12))
    entry_busqueda.grid(row=0, column=1, padx=10, pady=10)

    boton_buscar = tk.Button(libros_disponibles, text="Buscar",
                             command=lambda: buscar_libros(entry_busqueda), font=("Arial", 12))
    boton_buscar.grid(row=1, column=0, padx=10, pady=10)

    libros_disponibles.mainloop()


def toogle_password(entry, boton):
    if entry.cget('show') == '*':
        entry.config(show='')
        boton.config(text='Ocultar')
    else:
        entry.config(show='*')
        boton.config(text='Mostrar')


def abrir_registro():
    ventana_registro = tk.Toplevel()
    ventana_registro.title("Registro de usuario")
    ventana_registro.geometry("600x400")
    ventana_registro.resizable(False, False)

    (tk.Label(ventana_registro, text="Nuevo usuario:", font=("Arial", 12))
     .grid(row=0, column=0, padx=10, pady=10, sticky="e"))
    (tk.Label(ventana_registro, text="Password:", font=("Arial", 12))
     .grid(row=1, column=0, padx=10, pady=10, sticky="e"))

    entry_nuevo_usuario = tk.Entry(ventana_registro, font=("Arial", 12))
    entry_nueva_password = tk.Entry(ventana_registro, show="*", font=("Arial", 12))

    entry_nuevo_usuario.grid(row=0, column=1, padx=10, pady=10)
    entry_nueva_password.grid(row=1, column=1, padx=10, pady=10)

    boton_toogle_registro = tk.Button(ventana_registro, text="Mostrar",
                                      command=lambda: toogle_password(entry_nueva_password, boton_toogle_registro),
                                      font=("Arial", 12))
    boton_toogle_registro.grid(row=1, column=2, padx=10, pady=10)

    def registrar_usuario():
        nuevo_usuario = entry_nuevo_usuario.get()
        nueva_password = entry_nueva_password.get()

        if not nuevo_usuario or not nueva_password:
            messagebox.showerror('Error', 'Por favor, introduce usuario y contraseña')
            return

        if registrar_nuevo_usuario(nuevo_usuario, nueva_password):
            messagebox.showinfo('Registro exitoso', 'Usuario registrado exitosamente')
            ventana_registro.destroy()
        else:
            messagebox.showerror('Error', 'Error al registrar usuario')

    boton_registrar = tk.Button(ventana_registro, text="Registrar", command=registrar_usuario, font=("Arial", 12))
    boton_registrar.grid(row=2, column=1, padx=10, pady=10)


def validar_credenciales(usuario, password):
    if not os.path.exists(USER_DATA_FILE):
        return False

    with open(USER_DATA_FILE, 'r') as f:
        for line in f:
            u, hashed = line.strip().split(',')
            if u == usuario and bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8')):
                return True

    return False


def registrar_nuevo_usuario(usuario, password):
    if not os.path.exists(USER_DATA_FILE):
        open(USER_DATA_FILE, 'w').close()

        with open(USER_DATA_FILE, 'r') as f:
            for line in f:
                u, _ = line.strip().split(',')
                if u == usuario:
                    return False

    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    with open(USER_DATA_FILE, 'a') as f:
        f.write(f"{usuario},{hashed.decode('utf-8')}\n")
        return True


def cargar_recordar():
    if os.path.exists(REMEMBER_ME_FILE):
        with open(REMEMBER_ME_FILE, 'r') as f:
            line = f.readline().strip()
            if line:
                usuario, password = line.split(',')
                entry_usuario.insert(0, usuario)
                entry_password.insert(0, password)
                var_recordar.set(1)
    return None


ventana_acceso = tk.Tk()
ventana_acceso.title("Formulario de acceso")
ventana_acceso.geometry("600x400")
ventana_acceso.resizable(False, False)

tk.Label(ventana_acceso, text="Usuario:", font=("Arial", 12)).grid(row=0, column=0, padx=10, pady=10, sticky="e")
tk.Label(ventana_acceso, text="Contraseña:", font=("Arial", 12)).grid(row=1, column=0, padx=10, pady=10, sticky="e")

entry_usuario = tk.Entry(ventana_acceso, font=("Arial", 12))
entry_password = tk.Entry(ventana_acceso, show="*", font=("Arial", 12))

entry_usuario.grid(row=0, column=1, padx=10, pady=10)
entry_password.grid(row=1, column=1, padx=10, pady=10)

boton_toogle = tk.Button(ventana_acceso, text="Mostrar", command=lambda: toogle_password(entry_password, boton_toogle),
                         font=("Arial", 12))
boton_toogle.grid(row=1, column=2, padx=10, pady=10)

var_recordar = tk.IntVar()
chk_recordar = tk.Checkbutton(ventana_acceso, text="Recordar usuario", variable=var_recordar, font=("Arial", 12))
chk_recordar.grid(row=2, column=0, padx=10, pady=10, sticky="w")

boton_acceso = tk.Button(ventana_acceso, text="Acceder", command=validar_acceso, font=("Arial", 12))
boton_acceso.grid(row=2, column=1, padx=10, pady=10)

boton_registro = tk.Button(ventana_acceso, text="Registrarse", command=abrir_registro, font=("Arial", 12))
boton_registro.grid(row=3, column=0, padx=10, pady=10)

boton_salir = tk.Button(ventana_acceso, text="Salir", command=ventana_acceso.destroy, font=("Arial", 12))
boton_salir.grid(row=2, column=2, padx=10, pady=10)

cargar_recordar()

ventana_acceso.mainloop()
