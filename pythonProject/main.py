import pyhibp
from pyhibp import pwnedpasswords as pawned
from flask_restful import Api
import random
import string
import datetime,re
import bcrypt
import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)
api = Api(app)
SECRET_KEY = 'Secret_Key'

def token_verified(token):
    if not token:
        return False
    try:
        jwt.decode(token, SECRET_KEY, algorithm="HS256")
        return True
    except Exception as e:
        return False

def generate_token(username):
    SECRET_KEY = 'Th1s1ss3cr3t'
    token = jwt.encode(
        {'public_id': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
        SECRET_KEY, algorithm="HS256")
    return jsonify({'token': token})

@app.route('/create-password', methods=['POST'])
def create_password():
    username = request.get_json()['username']
    password = request.get_json()['password']
    confirm_password = request.get_json()['confirm_password']
    system = request.get_json()['system']
    token = None
    if 'token' in request.headers:
        token = request.headers['token']

    if not token_verified(token):
        return jsonify({'message': 'A Valid Token is Missing'}, 401)
    if password != confirm_password:
        return jsonify({"message " : " Passwords do not match "})
    # need to check if user already exists
    response = check_password_complexity(password)
    if response == False:
        return jsonify("The complexity criteria is not matched")
    if check_pawned(password):
        return jsonify("The password is pawned")

    hashed_password = hash_password(password)
    # save password
    save_password(username, hashed_password, str(datetime.datetime.now()))
    return jsonify({"message ":"The password is successfully created and saved"})


def check_pawned(password):
    # Setting the User-Agent to be used in subsequent calls sent to the HIBP API backend.
    pyhibp.set_user_agent(ua="PMS")
    # Check if a password has been disclosed in any of the data breaches
    resp = pawned.is_password_breached(password=password)
    return resp


@app.route('/admin-login', methods=['POST'])
def login():
    username = request.get_json()['username']
    password = request.get_json()['password']
    if username == "admin" and password == "admin":
        return generate_token(username)
    return "Invalid credentials", 400


@app.route('/generate-password', methods=['POST'])
def generate_password():
    username = request.get_json()['username']
    system = request.get_json()['system']
    # need to check if user already exists
    generated_password = ''.join(random.choices(string.ascii_letters + string.digits + "&$@_*", k=10))
    hashed_password = hash_password(generated_password)
    # save password
    save_password(username, hashed_password,str(datetime.datetime.now()))
    return jsonify({"message ": "The password is successfully created and saved",
                    "hashed_password": str(hashed_password)})


def hash_password(password):
    # encrypt user entered password
    raw_password = bytes(password, 'utf-8')
    salt = bcrypt.gensalt(12)
    hashed_password = bcrypt.hashpw(raw_password, salt)
    return hashed_password


def save_password(username, hashed_password, date):
    sample_line = [username, str(hashed_password), str(date)]
    with open('db_file.txt', 'a+') as db_write:
        db_write.write(' '.join(sample_line))
        db_write.write('\n')


@app.route('/renew', methods=['POST'])
def renew():
    username = request.get_json()['username']
    password = request.get_json()['password']
    confirm_password = request.get_json()['confirm_password']
    if not confirm_password == password:
        return jsonify("Passwords do not match")
    response = check_password_complexity(password)
    if response == "False":
        return jsonify("The complexity criteria is not matched")
    hash = hash_password(password)
    with open("db_file.txt", "r") as file_input:
        lines = file_input.readlines()
    with open("db_file.txt", "w") as f:
        for line in lines:
            if line.split(' ')[0] != username:
                f.write(line)
        date = datetime.datetime.now()
        sample_line = [username, str(hash), str(date)]
        f.write(' '.join(sample_line))
        f.write('\n')
        f.close()
    return jsonify("details updated"), 200


def check_password_complexity(password):
    if len(password) < 8 and re.search("\s", password) \
            or not re.search("[a-z]", password) \
            or not re.search("[A-Z]", password) \
            or not re.search("[0-9]", password) \
            or not re.search("[@!#$&%*]", password):
        criteria_satisfied = False
    else:
        criteria_satisfied = True
    return criteria_satisfied


if __name__ == '__main__':
    app.run(debug=True)


