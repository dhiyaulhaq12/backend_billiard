from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_mail import Mail, Message
from flask_cors import CORS
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta
import random
import string
import traceback
from config import MONGO_URI, SECRET_KEY, JWT_SECRET_KEY, MAIL_SERVER, MAIL_PORT, MAIL_USERNAME, MAIL_PASSWORD, MAIL_USE_TLS

app = Flask(__name__)
CORS(app)

# MongoDB Config
app.config["MONGO_URI"] = MONGO_URI
app.config["SECRET_KEY"] = SECRET_KEY
app.config["JWT_SECRET_KEY"] = JWT_SECRET_KEY

# Mail Config
app.config['MAIL_SERVER'] = MAIL_SERVER
app.config['MAIL_PORT'] = MAIL_PORT
app.config['MAIL_USERNAME'] = MAIL_USERNAME
app.config['MAIL_PASSWORD'] = MAIL_PASSWORD
app.config['MAIL_USE_TLS'] = MAIL_USE_TLS
app.config['MAIL_USE_SSL'] = False

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
mail = Mail(app)

datetime.utcnow()

@app.errorhandler(Exception)
def handle_exception(e):
    print(traceback.format_exc())
    return jsonify({"error": str(e)}), 500

def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))

# =================== REGISTER (OTP dikirim) ====================
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not email or not password or not username:
        return jsonify({'message': 'Semua field wajib diisi'}), 400

    if mongo.db.users.find_one({'email': email}):
        return jsonify({'message': 'Email sudah digunakan'}), 409

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    otp = generate_otp()

    user_data = {
    'username': username,
    'email': email,
    'password': hashed_password,
    'is_verified': False,
    'otp': otp,
    'otp_expiry': datetime.utcnow() + timedelta(minutes=1),  # OTP berlaku 1 menit
    'created_at': datetime.utcnow()
}
    
    print("=== DATA YANG DIINSERT ===")
    print(user_data)

    mongo.db.users.insert_one(user_data)

    # Kirim email OTP
    msg = Message('Kode OTP Registrasi', sender=MAIL_USERNAME, recipients=[email])
    msg.body = f"Kode OTP kamu adalah: {otp}. Jangan berikan kepada siapa pun."
    mail.send(msg)

    return jsonify({'message': 'OTP telah dikirim ke email kamu'}), 200

# =================== VERIFIKASI OTP ====================
@app.route('/otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    email = data.get('email')
    otp_input = data.get('otp')

    user = mongo.db.users.find_one({'email': email})
    if not user:
        return jsonify({'message': 'User tidak ditemukan'}), 404

    if user['is_verified']:
        return jsonify({'message': 'Akun sudah terverifikasi'}), 400

    if datetime.utcnow() > user.get('otp_expiry', datetime.utcnow()):
        return jsonify({'message': 'OTP telah kedaluwarsa, silakan daftar ulang'}), 400
    
    print(f"OTP dari input: {otp_input}")
    print(f"OTP dari database: {user['otp']}")


    if str(user['otp']) != str(otp_input):
        return jsonify({'message': 'Kode OTP salah'}), 401

    mongo.db.users.update_one(
        {'_id': user['_id']},
        {'$set': {'is_verified': True}, '$unset': {'otp': "", 'otp_expiry': ""}}
    )

    return jsonify({'message': 'Verifikasi berhasil. Silakan login.'}), 200



# =================== LOGIN ====================
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = mongo.db.users.find_one({'email': email})
    if not user or not bcrypt.check_password_hash(user['password'], password):
        return jsonify({'message': 'Email atau password salah'}), 401

    if not user.get('is_verified'):
        return jsonify({'message': 'Akun belum diverifikasi. Cek email OTP kamu.'}), 403

    access_token = create_access_token(identity=str(user['_id']), expires_delta=timedelta(hours=1))

    return jsonify({
        'access_token': access_token,
        'message': 'Login berhasil'
    }), 200

@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    data = request.get_json()
    email = data.get('email')

    user = mongo.db.users.find_one({'email': email})
    if not user:
        return jsonify({'message': 'User tidak ditemukan'}), 404

    if user['is_verified']:
        return jsonify({'message': 'Akun sudah diverifikasi'}), 400

    now = datetime.utcnow()  # perbaikan di sini
    otp_expiry = user.get('otp_expiry', now)

    # Pastikan hanya bisa request OTP baru jika OTP sebelumnya sudah expired
    if now < otp_expiry:
        sisa_detik = int((otp_expiry - now).total_seconds())
        return jsonify({'message': f'Harap tunggu {sisa_detik} detik untuk kirim ulang OTP'}), 400

    # Buat OTP baru dan update di database
    new_otp = generate_otp()
    new_expiry = now + timedelta(minutes=1)  # perbaikan di sini

    mongo.db.users.update_one(
        {'_id': user['_id']},
        {'$set': {'otp': new_otp, 'otp_expiry': new_expiry}}
    )

    # Kirim ulang email OTP
    msg = Message('Kode OTP Baru', sender=MAIL_USERNAME, recipients=[email])
    msg.body = f"Kode OTP terbaru kamu adalah: {new_otp}. Jangan berikan kepada siapa pun."
    mail.send(msg)

    return jsonify({'message': 'Kode OTP baru telah dikirim ke email kamu'}), 200


# =================== GET USER (PROTECTED) ====================
@app.route('/user', methods=['GET'])
@jwt_required()
def get_user():
    user_id = get_jwt_identity()
    user = mongo.db.users.find_one({'_id': ObjectId(user_id)})

    if not user:
        return jsonify({'message': 'User tidak ditemukan'}), 404

    # response user
    user_data = {
        'id': str(user['_id']),
        'username': user['username'],
        'email': user['email'],
        'created_at': user['created_at'].strftime('%Y-%m-%d %H:%M:%S')
    }

    return jsonify({'user': user_data}), 200

@app.route('/<user_id>/update', methods=['PATCH'])
def update_profile(user_id):
    users_collection = mongo.db.users

    try:
        user = users_collection.find_one({'_id': ObjectId(user_id)})
    except Exception:
        return jsonify({'message': 'Invalid user ID'}), 400

    if not user:
        return jsonify({'message': 'User not found'}), 404

    username = request.form.get('username')
    password = request.form.get('password')

    update_data = {'updated_at': datetime.utcnow()}

    if username:
        update_data['username'] = username

    if password:
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        update_data['password'] = hashed_password

    users_collection.update_one({'_id': ObjectId(user_id)}, {'$set': update_data})

    updated_user = users_collection.find_one({'_id': ObjectId(user_id)})

    return jsonify({
        'message': 'Profile updated successfully',
        'user': {
            'id': str(updated_user['_id']),
            'username': updated_user.get('username'),
            'email': updated_user.get('email'),
            'created_at': updated_user.get('created_at'),
            'updated_at': updated_user.get('updated_at')
        }
    }), 200

@app.route('/', methods=["GET"])
def hello ():
    return jsonify({
        "msg": "API is ready"
    })

# =================== RUN APP ====================
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
