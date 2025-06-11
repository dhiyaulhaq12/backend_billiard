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
import os
from werkzeug.utils import secure_filename
import cloudinary.uploader
import cloudinary
from config import cloudinary_config

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

cloudinary.config(
    cloud_name=cloudinary_config["cloud_name"],
    api_key=cloudinary_config["api_key"],
    api_secret=cloudinary_config["api_secret"],
    secure=True
)

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
    platform = data.get('platform', 'unknown')
    ip_address = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', '127.0.0.1')

    user = mongo.db.users.find_one({'email': email})
    if not user or not bcrypt.check_password_hash(user['password'], password):
        return jsonify({'message': 'Email atau password salah'}), 401

    if not user.get('is_verified'):
        return jsonify({'message': 'Akun belum diverifikasi. Cek email OTP kamu.'}), 403

    access_token = create_access_token(identity=str(user['_id']), expires_delta=timedelta(hours=1))
    
    mongo.db.login_logs.insert_one({
        'user_id': str(user['_id']),
        'platform': platform,
        'ip_address': ip_address,
        'status': 'login',
        'login_time': datetime.utcnow(),
        'last_activity': datetime.utcnow(),
        'logout_time': None
    })

    return jsonify({
        'success': True,
        'message': 'Login berhasil',
        'access_token': access_token,
        'user_id': str(user['_id']),
        'username': user.get('username', '')
    }), 200


@app.route('/activity', methods=['POST'])
@jwt_required()
def update_activity():
    user_id = get_jwt_identity()
    ip_address = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', '127.0.0.1')
    platform = request.json.get('platform', 'unknown')

    mongo.db.login_logs.update_one(
        {
            'user_id': user_id,
            'platform': platform,
            'ip_address': ip_address,
            'status': 'login',
            'logout_time': None
        },
        {
            '$set': {
                'last_activity': datetime.utcnow()
            }
        }
    )
    return jsonify({'message': 'Aktivitas terakhir diperbarui'}), 200

@app.route('/activity/<log_id>', methods=['DELETE'])
@jwt_required()
def delete_activity_log(log_id):
    try:
        user_id = get_jwt_identity()
        print(f"Delete single log - User ID: {user_id}, Log ID: {log_id}")
        
        # Validasi user_id
        if not user_id:
            return jsonify({'message': 'User ID tidak ditemukan dalam token'}), 422
        
        # Validasi ObjectId
        try:
            object_id = ObjectId(log_id)
        except Exception as e:
            print(f"Invalid ObjectId: {e}")
            return jsonify({'message': 'ID log tidak valid'}), 400
        
        # Cari dan hapus log berdasarkan _id dan user_id (untuk security)
        result = mongo.db.login_logs.delete_one({
            '_id': object_id,
            'user_id': user_id
        })
        
        print(f"Delete result - Deleted count: {result.deleted_count}")
        
        if result.deleted_count == 0:
            return jsonify({'message': 'Log aktivitas tidak ditemukan atau Anda tidak memiliki akses'}), 404
        
        return jsonify({
            'status': 'success',
            'message': 'Log aktivitas berhasil dihapus'
        }), 200
        
    except Exception as e:
        print(f"Error deleting single log: {str(e)}")
        return jsonify({'message': f'Terjadi kesalahan: {str(e)}'}), 500

# Endpoint untuk delete all activity logs untuk user tertentu
@app.route('/activity/all', methods=['DELETE'])
@jwt_required()
def delete_all_activity_logs():
    try:
        user_id = get_jwt_identity()
        print(f"Delete all logs - User ID: {user_id}")
        
        # Validasi user_id
        if not user_id:
            return jsonify({'message': 'User ID tidak ditemukan dalam token'}), 422
        
        # Hapus semua logs untuk user ini
        result = mongo.db.login_logs.delete_many({'user_id': user_id})
        
        print(f"Delete all result - Deleted count: {result.deleted_count}")
        
        return jsonify({
            'status': 'success',
            'message': f'Berhasil menghapus {result.deleted_count} log aktivitas',
            'deleted_count': result.deleted_count
        }), 200
        
    except Exception as e:
        print(f"Error deleting all logs: {str(e)}")
        return jsonify({'message': f'Terjadi kesalahan: {str(e)}'}), 500

# Perbaikan untuk endpoint GET (menambahkan field 'id')
@app.route('/activity', methods=['GET'])
@jwt_required()
def get_activity_logs():
    try:
        user_id = get_jwt_identity()
        print(f"User ID dari JWT: {user_id}")
        
        # Validasi user_id
        if not user_id:
            return jsonify({'message': 'User ID tidak ditemukan dalam token'}), 422
        
        # Cari logs berdasarkan user_id
        logs = list(mongo.db.login_logs.find({'user_id': user_id}))
        print(f"Jumlah logs ditemukan: {len(logs)}")
        
        # Proses setiap log
        processed_logs = []
        for log in logs:
            processed_log = {
                'id': str(log['_id']),  # Tambahkan field 'id' untuk frontend
                '_id': str(log['_id']),
                'user_id': log.get('user_id'),
                'platform': log.get('platform', 'Unknown'),
                'login_time': log['login_time'].isoformat() if log.get('login_time') else None,
                'last_activity': log['last_activity'].isoformat() if log.get('last_activity') else None,
                'logout_time': log['logout_time'].isoformat() if log.get('logout_time') else None,
                'ip_address': log.get('ip_address', 'Unknown'),
                'user_agent': log.get('user_agent', 'Unknown')
            }
            processed_logs.append(processed_log)
        
        return jsonify({
            'status': 'success',
            'message': f'Berhasil mengambil {len(processed_logs)} log aktivitas',
            'logs': processed_logs
        }), 200
        
    except Exception as e:
        print(f"Error getting activity logs: {str(e)}")
        return jsonify({'message': f'Terjadi kesalahan: {str(e)}'}), 500



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
        'profile_picture': user.get('profile_picture'),
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
    old_password = request.form.get('old_password')
    file = request.files.get('profile_picture')

    update_data = {'updated_at': datetime.utcnow()}

    if username:
        update_data['username'] = username

    if password:
        if not old_password:
            return jsonify({'message': 'Password lama wajib diisi'}), 400

        if not bcrypt.check_password_hash(user['password'], old_password):
            return jsonify({'message': 'Password lama salah'}), 401

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        update_data['password'] = hashed_password

    if file:
        try:
            upload_result = cloudinary.uploader.upload(file, folder="profile_pictures")
            image_url = upload_result.get("secure_url")
            update_data['profile_picture'] = image_url
        except Exception as e:
            return jsonify({'message': f'Gagal upload gambar: {str(e)}'}), 500

    users_collection.update_one({'_id': ObjectId(user_id)}, {'$set': update_data})

    updated_user = users_collection.find_one({'_id': ObjectId(user_id)})

    return jsonify({
        'message': 'Profile updated successfully',
        'user': {
            'id': str(updated_user['_id']),
            'username': updated_user.get('username'),
            'email': updated_user.get('email'),
            'profile_picture': updated_user.get('profile_picture'),
            'created_at': updated_user.get('created_at'),
            'updated_at': updated_user.get('updated_at')
        }
    }), 200
    
@app.route('/videos', methods=['GET'])
def get_videos():
    videos_collection = mongo.db.youtube_billiard
    videos = list(videos_collection.find({}, {"_id": 0, "title": 1, "description": 1, "link": 1, "channel": 1}))
    return jsonify(videos)

@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    print("=== LOGOUT ENDPOINT DIPANGGIL ===")
    user_id = get_jwt_identity()
    ip_address = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', '127.0.0.1')
    platform = request.json.get('platform', 'unknown')
    
    print(f"User ID: {user_id}")
    print(f"IP Address: {ip_address}")
    print(f"Platform: {platform}")

    # Temukan login log terbaru berdasarkan user_id, ip, dan platform
    latest_log = mongo.db.login_logs.find_one(
        {
            'user_id': user_id,
            'platform': platform,
            'ip_address': ip_address,
            'status': 'login',
            'logout_time': None
        },
        sort=[('login_time', -1)]
    )
    
    print(f"Latest log found: {latest_log}")

    if latest_log:
        print(f"Updating log with ID: {latest_log['_id']}")
        result = mongo.db.login_logs.update_one(
            {'_id': latest_log['_id']},
            {
                '$set': {
                    'status': 'logout',
                    'logout_time': datetime.utcnow(),
                    'last_activity': datetime.utcnow()
                }
            }
        )
        print(f"Update result: {result.modified_count} documents modified")
    else:
        print("No matching login log found!")

    return jsonify({'message': 'Logout berhasil'}), 200




@app.route('/', methods=["GET"])
def hello ():
    return jsonify({
        "msg": "API is ready"
    })

# =================== RUN APP ====================
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
