import psycopg2
import jwt
from flask import Flask, request, jsonify
from datetime import datetime, timedelta
from functools import wraps
from flask_bcrypt import Bcrypt
from flask_bcrypt import generate_password_hash
from flask_bcrypt import check_password_hash
from datetime import datetime

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = "this is secret"

conn = psycopg2.connect(
    database='projectf',
    host='localhost',
    user='postgres',
    password='1234',
    port='5432'
)

cur = conn.cursor()


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'token is missing'}), 403
        try:
            token = token.split(" ")[1]
            payload = jwt.decode(
                token, app.config['SECRET_KEY'], algorithms=['HS256'])
            return f(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'token has expired'}), 403
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid Token'}), 403
    return decorated


def role_required(role_id):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            token = request.headers.get('Authorization')
            if token:
                try:
                    token = token.split(" ")[1]
                    payload = jwt.decode(
                        token, app.config['SECRET_KEY'], algorithms=["HS256"])
                    user_role = payload.get('role_id')
                    
                    if user_role[0] == role_id:
                        return func(*args, **kwargs)
                    # elif user_role[0] == role_id:
                    #     return jsonify(data)
                    else:
                        return jsonify({'error': 'insufficient permission'})
                except jwt.ExpiredSignatureError:
                    return jsonify({'error': 'Token has expired'}), 401
                except jwt.InvalidTokenError:
                    return jsonify({'error': 'Token is invalid'}), 401
            else:
                return jsonify({'error': 'Token is missing'}), 401
        return wrapper
    return decorator


@app.route('/signup/user', methods=['POST'])
def signup():
    data = request.json
    uid = data.get("uid")
    uname = data.get("uname")
    email = data.get("email")
    password = data.get("password")
    role_id = data.get("role_id")
    cur.execute('''SeLECT * FROM users where email=%s''', (email,))
    existing_user = cur.fetchone()
    if existing_user:
        return jsonify({'message': 'User already exists'}), 400
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    cur.execute('''INSERT INTO users(uid,uname,email,password,role_id) VALUES(%s,%s,%s,%s,%s)''',
                (uid, uname, email, hashed_password, role_id))
    conn.commit()
    return "Registerd successfully"


@app.route('/login/user', methods=['POST'])
def login():
    data = request.json
    email = data.get("email")
    password = data.get("password")
    cur.execute('''SELECT role_id FROM users where email=%s''', (email,))
    rid = cur.fetchone()
    cur.execute('''SELECT password FROM users where email=%s''', (email,))
    user = cur.fetchone()
    if user:
        hashed_password = user[0]
        if check_password_hash(hashed_password, password):
            token = jwt.encode({
                'email': email,
                'role_id': rid,
                'exp': datetime.utcnow() + timedelta(seconds=9900)
            }, app.config['SECRET_KEY'], algorithm='HS256')
            conn.commit()
            return jsonify({'token': token}), 201
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
    else:
        return jsonify({'error': 'User not found'}), 404


blacklist = set()
@app.route('/logout/user', methods=['POST'])
@token_required
def logout():
    token = request.headers.get('Authorization')
    if token:
        token = token.split()[1]
        blacklist.add(token)
        return jsonify({'message': 'logged out'}), 200
    else:
        return jsonify({'error': 'token is missing'}), 403


@app.route('/get_admin', methods=['GET'])
@role_required(2)
def get_admin():
    role_id=payload.get('role_id')
    cur.execute('''select * from users where role_id=%s''', (role_id,))
    data = cur.fetchall()
    return jsonify(data)


@app.route('/get_users', methods=['GET'])
@role_required(1)
def get_users():
    return 'users'


@app.route('/create_post', methods=['POST'])
@role_required(1)
def create():
    data = request.json
    pid = data.get('id')
    content = data.get('content')
    likes = data.get('likes')
    uid = data.get('uid')
    id = data.get('id')
    current_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    cur.execute('''insert into post(pid,content,likes,created_at,uid,id) values(%s,%s,%s,%s,%s,%s)''',
                (pid, content, likes, current_time, uid, id))
    conn.commit()
    return jsonify(data)


@app.route('/get_posts', methods=['GET'])
@role_required(2)
def get_posts():
    cur.execute('''select pid,content,created_at from post''')
    data = cur.fetchall()
    return jsonify(data)


if __name__ == '__main__':
    app.run(debug=True)

cur.close()
conn.close()
