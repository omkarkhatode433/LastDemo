import os
from flask import Flask, request, redirect, render_template, send_file, flash
from werkzeug.utils import secure_filename
import DH
import pickle
import random

UPLOAD_FOLDER = './media/text-files/'
UPLOAD_KEY = './media/public-keys/'
ALLOWED_EXTENSIONS = {'txt'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def post_upload_redirect():
    return render_template('post-upload.html')

@app.route('/register')
def call_page_register_user():
    return render_template('register.html')

@app.route('/home')
def back_home():
    return render_template('index.html')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload-file')
def call_page_upload():
    return render_template('upload.html')

@app.route('/public-key-directory/retrieve/key/<username>')
def download_public_key(username):
    for root, dirs, files in os.walk('./media/public-keys/'):
        for file in files:
            list = file.split('-')
            if list[0] == username:
                filename = UPLOAD_KEY + file
                return send_file(filename, download_name='publicKey.pem', as_attachment=True)

@app.route('/file-directory/retrieve/file/<filename>')
def download_file(filename):
    filepath = UPLOAD_FOLDER + filename
    if os.path.isfile(filepath):
        return send_file(filepath, download_name='fileMessage-thrainSecurity.txt', as_attachment=True)
    else:
        return render_template('file-list.html', msg='An issue encountered, our team is working on that')

@app.route('/public-key-directory/')
def downloads_pk():
    username = []
    if os.path.isfile("./media/database/database_1.pickle"):
        with open("./media/database/database_1.pickle", "rb") as pickleObj:
            username = pickle.load(pickleObj)
    if len(username) == 0:
        return render_template('public-key-list.html', msg='Aww snap! No public key found in the database')
    else:
        return render_template('public-key-list.html', msg='', itr=0, length=len(username), directory=username)

@app.route('/file-directory/')
def download_f():
    for root, dirs, files in os.walk(UPLOAD_FOLDER):
        if len(files) == 0:
            return render_template('file-list.html', msg='Aww snap! No file found in directory')
        else:
            return render_template('file-list.html', msg='', itr=0, length=len(files), list=files)
    return render_template('file-list.html', msg='An issue encountered, our team is working on that')

@app.route('/data', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return 'NO FILE SELECTED'
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return post_upload_redirect()
        return 'Invalid File Format!'

@app.route('/register-new-user', methods=['GET', 'POST'])
def register_user():
    private_key_list = []
    username_list = []

    if os.path.isfile("./media/database/database.pickle"):
        with open("./media/database/database.pickle", "rb") as pickle_file:
            private_key_list = pickle.load(pickle_file)

    if os.path.isfile("./media/database/database_1.pickle"):
        with open("./media/database/database_1.pickle", "rb") as pickle_file:
            username_list = pickle.load(pickle_file)

    new_username = request.form['username']
    if new_username in username_list:
        return render_template('register.html', name='Username already exists')

    pin = random.randint(1, 128) % 64
    private_key = DH.generate_private_key(pin)
    while private_key in private_key_list:
        pin = random.randint(1, 128) % 64
        private_key = DH.generate_private_key(pin)

    private_key_list.append(private_key)
    username_list.append(new_username)

    with open("./media/database/database.pickle", "wb") as pickle_file:
        pickle.dump(private_key_list, pickle_file)

    with open("./media/database/database_1.pickle", "wb") as pickle_file:
        pickle.dump(username_list, pickle_file)

    firstname = request.form['first-name']
    secondname = request.form['last-name']
    filename = UPLOAD_KEY + new_username + '-' + secondname.upper() + firstname.lower() + '-PublicKey.pem'

    public_key = DH.generate_public_key(private_key)
    with open(filename, "w") as public_key_file:
        public_key_file.write(str(public_key))

    return render_template('key-display.html', privatekey=str(private_key))

if __name__ == '__main__':
    app.run(debug=True)
