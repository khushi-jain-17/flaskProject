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


# @app.route('/signup/user', methods=['POST'])
# def signup():
#     data = request.json
#     uid = data.get("uid")
#     uname = data.get("uname")
#     email = data.get("email")
#     password = data.get("password")
#     role_id = data.get("role_id")
#     cur.execute('''SeLECT * FROM users where email=%s''', (email,))
#     existing_user = cur.fetchone()
#     if existing_user:
#         return jsonify({'message': 'User already exists'}), 400
#     hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
#     cur.execute('''INSERT INTO users(uid,uname,email,password,role_id) VALUES(%s,%s,%s,%s,%s)''',
#                 (uid, uname, email, hashed_password, role_id))
#     conn.commit()
#     return "Registerd Successfully"


@app.route('/signup/user', methods=['POST'])
def signup():
    data = request.json
    id = data.get("id")
    uid = data.get("uid")
    uname = data.get("uname")
    email = data.get("email")
    password = data.get("password")
    role_id = data.get("role_id")
    cur.execute('''select * FROM users where id=%s''', (id,))
    existing_user = cur.fetchone()
    if existing_user:
        return jsonify({'message': 'User already exists'}), 400
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    cur.execute('''INSERT INTO users(id,uid,uname,email,password,role_id) VALUES(%s,%s,%s,%s,%s,%s)''',
                (id,uid, uname, email, hashed_password, role_id))
    conn.commit()
    return "Registerd Successfully"

@app.route('/login/user', methods=['POST'])
def login():
    data = request.json
    id = data.get("id")
    password = data.get("password")
    cur.execute('''SELECT role_id FROM users where id=%s''', (id,))
    rid = cur.fetchone()
    cur.execute('''SELECT password FROM users where id=%s''', (id,))
    user = cur.fetchone()
    if user:
        hashed_password = user[0]
        if check_password_hash(hashed_password, password):
            token = jwt.encode({
                'id': id,
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
@token_required
def get_admin():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'token is missing'}), 403
    try:
        token = token.split(" ")[1]
        payload = jwt.decode(
            token, app.config['SECRET_KEY'], algorithms=['HS256'])
        role_id = payload.get('role_id')
        print(role_id[0])
        if role_id[0] == 2:
            cur.execute('''select * from users where role_id=%s''',
                        (role_id[0],))
            data = cur.fetchall()
            conn.commit()
            return jsonify(data)
        else:
            return jsonify({'error': 'insufficient permission'})
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'token has expired'}), 403
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid Token'}), 403


@app.route('/get_users', methods=['GET'])
@token_required
def get_users():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'token is missing'}), 403
    try:
        token = token.split(" ")[1]
        payload = jwt.decode(
            token, app.config['SECRET_KEY'], algorithms=['HS256'])
        role_id = payload.get('role_id')
        print(role_id[0])
        if role_id[0] == 1:
            cur.execute('''select * from users where role_id=%s''',
                        (role_id[0],))
            data = cur.fetchall()
            conn.commit()
            return jsonify(data)
        else:
            return jsonify({'error': 'insufficient permission'})
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'token has expired'}), 403
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid Token'}), 403


@app.route('/connect', methods=['POST'])
@role_required(1)
def connect_users():
    data = request.json
    cid = data.get('cid')
    follower_id = data.get('follower_id')
    following_id = data.get('following_id')
    cur.execute('''insert into connection(cid,follower_id,following_id) values(%s,%s,%s)''',
                (cid, follower_id, following_id))
    conn.commit()
    return jsonify(data)


@app.route('/create_post', methods=['POST'])
@role_required(1)
def create():
    data = request.json
    pid = data.get('pid')
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


@app.route('/get_post/<int:id>', methods=['GET'])
@role_required(2)
def get_post(id):
    cur.execute('''select pid,content,created_at from post where id=%s''', (id,))
    data = cur.fetchall()
    conn.commit()
    return jsonify(data)


@app.route('/update_post/<int:id>', methods=['PUT'])
@role_required(2)
def update_post(id):
    pid = request.json['pid']
    content = request.json['content']
    cur.execute(
        '''UPDATE post SET pid=%s, content=%s WHERE id=%s''', (
            pid, content, id,)
    )
    conn.commit()
    return jsonify({'message': 'item updated successfully'})


@app.route('/delete_post/<int:id>', methods=['DELETE'])
@role_required(2)
def delete_post(id):
    cur.execute('''delete from post where id=%s''', (id,))
    conn.commit()
    return jsonify({'message': 'Post deleted successfully'})


@app.route('/post_of_user/<string:uname>', methods=['GET'])
@role_required(1)
def posts_of_user(uname):
    # cur.execute(
    #     '''select pid,content,created_at from post where id=%s''', (id,))
    cur.execute(
        '''select post.content,post.created_at from post inner join users on post.uid=users.uid where users.uname=%s''', (uname,))
    data = cur.fetchall()
    conn.commit()
    return jsonify(data)


@app.route('/like_post', methods=['POST'])
@role_required(1)
def like_post():
    data = request.json
    pk = data.get('pk')
    uid = data.get('uid')
    likes = data.get('likes')
    pid = data.get('pid')
    cur.execute(
        '''insert into post(pk,uid,likes,pid) values(%s,%s,%s,%s)''', (pk,uid, likes, pid))
    conn.commit()
    return jsonify({'message':'Like'})


@app.route('/like_count/<int:pid>', methods=['GET'])
@role_required(1)
def count_likes(pid):
    cur.execute(
        '''select count(uid) from post where pid=%s and likes='True' ''', (pid,))
    data = cur.fetchall()
    return jsonify(data)


@app.route('/posts_liked_by_user/<int:uid>', methods=['GET'])
@role_required(1)
def posts_liked_by_user(uid):
    cur.execute('''select pid,content,likes from post where uid=%s''', (uid,))
    data = cur.fetchall()
    return jsonify(data)


@app.route('/liked_by/<int:pid>', methods=['GET'])
@role_required(1)
def people_liked_the_post(pid):
    cur.execute('''select users.uname, post.uid from users inner join post on users.uid=post.uid where post.pid=%s and likes='True' ''', (pid,))
    data = cur.fetchall()
    return jsonify(data)


@app.route('/home/<int:uid>', methods=['GET'])
@role_required(1)
def home(uid):
    cur.execute('''select pid from post where uid=%s and likes='True' ''', (uid,))
    p = cur.fetchone()
    cur.execute(
        '''select likedata.name,likedata.content, likedata.tc from likedata inner join post on likedata.uid = post.uid where post.pid=%s  ''',(p,))
    data = cur.fetchall()
    return jsonify(data)


@app.route('/create/likedata', methods=['POST'])
@role_required(2)
def create_likedata():
    data = request.json
    lid = data.get('lid')
    post_id = data.get('post_id')
    name = data.get('name')
    content = data.get('content')
    cur.execute(
        '''select count(uid) from post where pid=%s and likes='True' ''',(post_id,))
    total = cur.fetchone()
    cur.execute('''insert into likedata(lid,post_id,name,content,tc) values(%s,%s,%s,%s,%s)''',
                (lid, post_id, name, content, total))
    conn.commit()
    return jsonify(data)


if __name__ == '__main__':
    app.run(debug=True)

cur.close()
conn.close()
