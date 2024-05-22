import tkinter as tk
from tkinter import messagebox as ms
import sqlite3
from PIL import Image, ImageTk
import re
import random
import subprocess

def set_background_and_geometry(window):
    w, h = window.winfo_screenwidth(), window.winfo_screenheight()
    window.geometry("%dx%d+0+0" % (w, h))

    image2 = Image.open('bank.jpg')
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

def insert():
    fname = Fullname.get()
    addr = address.get()
    un = username.get()
    email = Email.get()
    mobile = Phoneno.get()
    gender = var.get()
    time = age.get()
    pwd = password.get()
    cnpwd = password1.get()
    
    # Validate email using regex
    regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
    if (re.search(regex, email)):
        a = True
    else:
        a = False

    # Validate other fields
    if (fname.isdigit() or (fname == "")):
        ms.showerror("Error", "Please enter a valid name")
    elif (addr == ""):
        ms.showerror("Error", "Please enter an address")
    elif (email == "") or (a == False):
        ms.showerror("Error", "Please enter a valid email")
    elif ((len(str(mobile))) < 10 or len(str((mobile))) > 10):
        ms.showerror("Error", "Please enter a 10-digit mobile number")
    elif ((time > 100) or (time == 0)):
        ms.showerror("Error", "Please enter a valid age")
    elif (pwd == ""):
        ms.showerror("Error", "Please enter a valid password")
    elif (var == False):
        ms.showinfo("Error", "Please enter a gender")
    elif (pwd == "") or (password_check(pwd)) != True:
        ms.showerror("Error", "Password must contain at least 1 uppercase letter, 1 symbol, 1 number")
    elif (pwd != cnpwd):
        ms.showerror("Error", "Password and Confirm password must be the same")
    else:
        conn = sqlite3.connect('evaluation.db')
        with conn:
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO registration (Fullname, address, username, Email, Phoneno, Gender, age , password) VALUES(?,?,?,?,?,?,?,?)',
                (fname, addr, un, email, mobile, gender, time, pwd))

            conn.commit()
            ms.showinfo('Success!', 'Account Created Successfully !')
            window.destroy()
            
            # Now, let's call 'bank_gui.py' using subprocess
            subprocess.run(["python", "login.py"])

# Create the main window
window = tk.Tk()
window.title("REGISTRATION FORM")
window.configure(background="grey")

set_background_and_geometry(window)

Fullname = tk.StringVar()
address = tk.StringVar()
username = tk.StringVar()
Email = tk.StringVar()
Phoneno = tk.IntVar()
var = tk.IntVar()
age = tk.IntVar()
password = tk.StringVar()
password1 = tk.StringVar()
policeno = tk.IntVar()
value = random.randint(1, 1000)
print(value)

l1 = tk.Label(window, text="Registration Form", font=("Times new roman", 30, "bold"), bg="#192841", fg="white")
l1.place(x=550, y=50)

l2 = tk.Label(window, text="Full Name :", width=12, font=("Times new roman", 15, "bold"), bg="snow")
l2.place(x=500, y=150)
t1 = tk.Entry(window, textvar=Fullname, width=20, font=('', 15))
t1.place(x=700, y=150)

l3 = tk.Label(window, text="Address :", width=12, font=("Times new roman", 15, "bold"), bg="snow")
l3.place(x=500, y=200)
t2 = tk.Entry(window, textvar=address, width=20, font=('', 15))
t2.place(x=700, y=200)

l5 = tk.Label(window, text="E-mail :", width=12, font=("Times new roman", 15, "bold"), bg="snow")
l5.place(x=500, y=250)
t4 = tk.Entry(window, textvar=Email, width=20, font=('', 15))
t4.place(x=700, y=250)

l6 = tk.Label(window, text="Phone number :", width=12, font=("Times new roman", 15, "bold"), bg="snow")
l6.place(x=500, y=300)
t5 = tk.Entry(window, textvar=Phoneno, width=20, font=('', 15))
t5.place(x=700, y=300)

l7 = tk.Label(window, text="Gender :", width=12, font=("Times new roman", 15, "bold"), bg="snow")
l7.place(x=500, y=350)
tk.Radiobutton(window, text="Male", padx=5, width=5, bg="snow", font=("bold", 15), variable=var, value=1).place(x=850,
                                                                                                                y=350)
tk.Radiobutton(window, text="Female", padx=20, width=4, bg="snow", font=("bold", 15), variable=var, value=2).place(
    x=700, y=350)

l8 = tk.Label(window, text="Age :", width=12, font=("Times new roman", 15, "bold"), bg="snow")
l8.place(x=500, y=400)
t6 = tk.Entry(window, textvar=age, width=20, font=('', 15))
t6.place(x=700, y=400)

l4 = tk.Label(window, text="User Name :", width=12, font=("Times new roman", 15, "bold"), bg="snow")
l4.place(x=500, y=450)
t3 = tk.Entry(window, textvar=username, width=20, font=('', 15))
t3.place(x=700, y=450)

l9 = tk.Label(window, text="Password :", width=12, font=("Times new roman", 15, "bold"), bg="snow")
l9.place(x=500, y=500)
t9 = tk.Entry(window, textvar=password, width=20, font=('', 15), show="*")
t9.place(x=700, y=500)

l10 = tk.Label(window, text="Confirm Password:", width=13, font=("Times new roman", 15, "bold"), bg="snow")
l10.place(x=500, y=550)

t10 = tk.Entry(window, textvar=password1, width=20, font=('', 15), show="*")
t10.place(x=700, y=550)

btn = tk.Button(window, text="Register", bg="#192841", font=("", 20), fg="white", width=9, height=0, command=insert)
btn.place(x=600, y=600)

window.mainloop()
