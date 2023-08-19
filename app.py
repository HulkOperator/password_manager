from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from func import login_required, error
import json
import random, string
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

class AESCipher(object):
    def __init__(self, key):
        self.block_size = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def __pad(self, plain_text):
        number_of_bytes_to_pad = self.block_size - len(plain_text) % self.block_size
        ascii_string = chr(number_of_bytes_to_pad)
        padding_str = number_of_bytes_to_pad * ascii_string
        padded_plain_text = plain_text + padding_str
        return padded_plain_text
    
    @staticmethod
    def __unpad(plain_text):
        last_character = plain_text[len(plain_text) - 1]
        bytes_to_remove = ord(last_character)
        return plain_text[:-bytes_to_remove]
    
    def encrypt(self, plain_text):
        plain_text = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text.encode())
        return base64.b64encode(iv + encrypted_text).decode('utf-8')
    
    def decrypt(self, encrypted_text):
        encrypted_text = base64.b64decode(encrypted_text)
        iv = encrypted_text[:self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain_text = cipher.decrypt(encrypted_text[self.block_size:]).decode('utf-8')
        return self.__unpad(plain_text)
    
aes_class_object = None

def update_encryption(password):
    user_id = session["user_id"]
    all_data = db.execute("SELECT * FROM enc_data WHERE user_id = ?", user_id)
    new_aes_object = AESCipher(password)
    global aes_class_object
    for data in all_data:
        id = data["id"]
        content = data["data"]
        content = aes_class_object.decrypt(content)
        content = new_aes_object.encrypt(content)
        db.execute("UPDATE enc_data SET data = ? WHERE id = ?", content, id)
    aes_class_object = new_aes_object

def password_strength(password):
    digits = string.digits
    upper = string.ascii_uppercase
    special = string.punctuation
    u, d, s = 0, 0, 0
    if len(password) < 8:
        return False
    for c in password:
        if c in upper:
            u += 1
        if c in digits:
            d += 1
        if c in special:
            s += 1

    if u > 0 and d > 0 and s > 0:
        return True
    return False

app = Flask(__name__)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///manager.db")

@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/")
@login_required
def index():
    user_id = session["user_id"]
    data = db.execute("SELECT * FROM enc_data WHERE user_id = ?;", user_id)
    
    if not data:
        return render_template("index.html")

    dict_data = []

    global aes_class_object
    

    for item in data:
        id = item["id"]
        item = item["data"]
        item = aes_class_object.decrypt(item)
        item = item.replace("'",'"')
        item = json.loads(item)
        item["id"] = id
        password = base64.b64decode(item["password"].encode("ascii")).decode("ascii")
        item["password"] = password
        dict_data.append(item)
    return render_template("index.html", items=dict_data, password=password)

@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()

    if request.method == "POST":
        if not request.form.get("username"):
            return error("username required")
        
        if not request.form.get("password"):
            return error("password required")
        
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return error("invalid username or password")
        
        session["user_id"] = rows[0]["id"]
        global aes_class_object 
        aes_class_object = AESCipher(request.form.get("password"))
        return redirect("/")

    else:
        return render_template("login.html")

    

@app.route("/logout")
@login_required
def logout():
    session.clear()

    return redirect("/")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if not request.form.get("username"):
            return error("username required")
        if not request.form.get("password"):
            return error("password required")
        if not request.form.get("confirmation"):
            return error("confirmation required")
        
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if password != confirmation:
            return error("Passwords do not match")
        
        user_check = len(db.execute("SELECT * FROM users WHERE username = ?", username))
        if user_check:
            return error("Username is already taken")

        if not password_strength(password):
            return error("password must be atleast 8 characters and contain a special character, number, and uppercase letter")
        id = len(db.execute("SELECT * FROM users;")) + 1

        db.execute("INSERT INTO users VALUES (?, ?, ?)", id, username, generate_password_hash(password))

        return redirect("/")
    else:
        return render_template("register.html")

@app.route("/add", methods=["GET", "POST"])
@login_required
def new_data():
    if request.method == "POST":

        user_id = session["user_id"]

        if not request.form.get("username"):
            return error("website required")
        if not request.form.get("username"):
            return error("username required")
        
        website = request.form.get("website")
        username = request.form.get("username")
        
        if request.form.get("cmd") == "generate":
            try:
                N = int(request.form.get("length"))
            except:
                N = 18
            password = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=N))
            
            return render_template("new.html", flag=1, website=website, username=username, password=password, len=N)
        else:
            if not request.form.get("password"):
                return error("password required")
            password = request.form.get("password")
            password = base64.b64encode(password.encode("ascii")).decode("ascii")
            
            
            data = {"website":website, "username":username, "password":password}
            global aes_class_object
            data = aes_class_object.encrypt(str(data))

            d_id = len(db.execute("SELECT * FROM enc_data;")) + 1

            db.execute("INSERT INTO enc_data VALUES (?, ?, ?);", d_id, user_id, data)

            return redirect("/")

    else:
        return render_template("new.html")
    
@app.route("/edit", methods=["POST"])
@login_required
def edit():
    user_id = session["user_id"]
    data_id = request.form.get("edit")
    if not data_id:
        return error("Unable to edit the data", 404)
    data_ids = db.execute("SELECT id FROM enc_data WHERE user_id = ?;", user_id)
    flag = 0
    for each_id in data_ids:
        if str(each_id["id"]) == str(data_id):
            flag = 1
            break
    if flag == 1:
        data = db.execute("SELECT data FROM enc_data WHERE id = ?", data_id)[0]["data"]
        data = aes_class_object.decrypt(data)
        data = data.replace("'", '"')
        data = json.loads(data)
        username = data["username"]
        website = data["website"]
        password = base64.b64decode(data["password"].encode("ascii")).decode("ascii")
        if request.form.get("cmd") == "generate":
            try:
                N = int(request.form.get("length"))
            except:
                N = 18
            password = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=N))
            return render_template("edit.html", data_id=data_id, website=website, username=username, password=password,generate=1,len=N)
        elif request.form.get("cmd") == "save":
            if not request.form.get("password"):
                return error("password required")
            password = request.form.get("password")
            password = base64.b64encode(password.encode("ascii")).decode("ascii")
            data = {"website":website, "username":username, "password":password}
            data = aes_class_object.encrypt(str(data))

            db.execute("UPDATE enc_data SET data = ? WHERE id = ?;", data, int(data_id))

            return redirect("/")
        else:
            return render_template("edit.html", data_id=data_id, website=website, username=username, password=password)
    else:
        return error("You do not have permission to make this change", 403)
    
@app.route("/delete", methods=["POST"])
@login_required
def delete():
    user_id = session["user_id"]
    data = db.execute("SELECT id FROM enc_data WHERE user_id = ?", user_id)
    data_id = request.form.get("delete")
    if not data_id:
        return error("Unable to delete data", 404)
    flag = 0
    for item in data:
        if str(item["id"]) == data_id:
            flag = 1
            break
    if flag == 0:
        return error("you are not authorized to delete this data", 403)
    db.execute("DELETE FROM enc_data WHERE id = ?;", data_id)
    return redirect("/")

@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    if request.method == "POST":
        user_id = session["user_id"]
        e_password = request.form.get("e_password")
        password =  request.form.get("password")
        confirmation = request.form.get("confirmation")
        
        if not e_password or not password or not confirmation:
            return error("sufficient information not provided")
        
        hash = db.execute("SELECT hash FROM users WHERE id = ?;", user_id)[0]["hash"]
        if not check_password_hash(hash, e_password):
            return error("wrong password")
        if password != confirmation:
            return error("new passwords do not match")
        
        if not password_strength(password):
            return error("password must be atleast 8 characters and contain a special character, number, and uppercase letter")

        hash = generate_password_hash(password)
        db.execute("UPDATE users SET hash = ? WHERE id = ?", hash, user_id)
        update_encryption(password)

        return redirect("/")

    else:
        return render_template("change.html")