import tkinter as tk
from tkinter import messagebox as ms
import sqlite3
from PIL import Image, ImageTk
from subprocess import call

def set_background_and_geometry(window):
    w, h = window.winfo_screenwidth(), window.winfo_screenheight()
    window.geometry("%dx%d+0+0" % (w, h))

    image2 = Image.open('dd.jpg')
    image2 = image2.resize((w, h), Image.BICUBIC)
    background_image = ImageTk.PhotoImage(image2)

    background_label = tk.Label(window, image=background_image)
    background_label.image = background_image
    background_label.place(x=0, y=0)

def password_check(passwd):
    SpecialSym = ['$', '@', '#', '%']
    val = True

    if len(passwd) < 6:
        print('length should be at least 6')
        val = False

    if len(passwd) > 20:
        print('length should not be greater than 8')
        val = False

    if not any(char.isdigit() for char in passwd):
        print('Password should have at least one numeral')
        val = False

    if not any(char.isupper() for char in passwd):
        print('Password should have at least one uppercase letter')
        val = False

    if not any(char.islower() for char in passwd):
        print('Password should have at least one lowercase letter')
        val = False

    if not any(char in SpecialSym for char in passwd):
        print('Password should have at least one of the symbols $@#')
        val = False
    if val:
        return val

def registration():
    call(["python", "registration.py"])
    root.destroy()

def login():
    # Establish Connection
    with sqlite3.connect('evaluation.db') as db:
        c = db.cursor()

        # Find user If there is any take proper action
        db = sqlite3.connect('evaluation.db')
        cursor = db.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS admin_registration"
                       "(Fullname TEXT, address TEXT, username TEXT, Email TEXT, Phoneno TEXT, Gender TEXT, age TEXT, password TEXT)")
        db.commit()

        find_entry = ('SELECT * FROM registration WHERE username = ?')
        c.execute(find_entry, [(username.get())])
        result = c.fetchall()

        if result:
            stored_password = result[0][-1]  # Assuming the last column is the password column
            if stored_password == password.get():
                ms.showinfo("Message", "Login successful")
                root.destroy()

                # Call bank_system_gui.py using subprocess
                call(['python', 'bank_gui.py'])
            else:
                ms.showerror('Oops!', 'Password Did Not Match.')
        else:
            ms.showerror('Oops!', 'Username Not Found.')


root = tk.Tk()
root.configure(background="black")
w, h = root.winfo_screenwidth(), root.winfo_screenheight()
root.geometry("%dx%d+0+0" % (w, h))
root.title("Login Form")

set_background_and_geometry(root)

username = tk.StringVar()
password = tk.StringVar()

title = tk.Label(root, text="Login Here", font=("Algerian", 30, "bold", "italic"), bd=5, bg="black", fg="white")
title.place(x=800, y=190, width=300)

Login_frame = tk.Frame(root, bg="#8B1C62")
Login_frame.place(x=700, y=300)

logolbl = tk.Label(Login_frame, bd=0).grid(row=0, columnspan=2, pady=20)

lbluser = tk.Label(Login_frame, text="Username", compound=tk.LEFT, font=("Times new roman", 20, "bold"), bg="white")
lbluser.grid(row=1, column=0, padx=20, pady=10)
txtuser = tk.Entry(Login_frame, bd=5, textvariable=username, font=("", 15))
txtuser.grid(row=1, column=1, padx=20)

lblpass = tk.Label(Login_frame, text="Password", compound=tk.LEFT, font=("Times new roman", 20, "bold"), bg="white")
lblpass.grid(row=2, column=0, padx=50, pady=10)
txtpass = tk.Entry(Login_frame, bd=5, textvariable=password, show="*", font=("", 15))
txtpass.grid(row=2, column=1, padx=20)

btn_log = tk.Button(Login_frame, text="Login", command=login, width=15, font=("Times new roman", 14, "bold"), bg="Green", fg="black")
btn_log.grid(row=3, column=1, pady=10)
btn_reg = tk.Button(Login_frame, text="Create Account", command=registration, width=15, font=("Times new roman", 14, "bold"), bg="red", fg="black")
btn_reg.grid(row=3, column=0, pady=10)

root.mainloop()
