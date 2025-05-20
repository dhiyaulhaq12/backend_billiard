from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token
import datetime
from config import MONGO_URI, DB_NAME, JWT_SECRET_KEY, SECRET_KEY
from flask_cors import CORS
from flask_jwt_extended import jwt_required, get_jwt_identity
from bson.objectid import ObjectId

app = Flask(__name__)
CORS(app)

# ✅ Konfigurasi MongoDB
app.config["MONGO_URI"] = f"{MONGO_URI}/{DB_NAME}"
app.config['SECRET_KEY'] = SECRET_KEY  # Pastikan SECRET_KEY ada di config
app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400

    existing_user = mongo.db.users.find_one({'email': email})
    if existing_user:
        return jsonify({'message': 'User already exists'}), 409

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    new_user = {
        'username': username,
        'email': email,
        'password': hashed_password,
        'created_at': datetime.datetime.utcnow()
    }

    mongo.db.users.insert_one(new_user)

    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400

    user = mongo.db.users.find_one({'email': email})
    if not user or not bcrypt.check_password_hash(user['password'], password):
        return jsonify({'message': 'Invalid email or password'}), 401

    expires = datetime.timedelta(hours=1)
    access_token = create_access_token(identity=str(user['_id']), expires_delta=expires)

    user_data = {
        'id': str(user['_id']),
        'username': user['username'],
        'email': user['email'],
        'created_at': user['created_at'].strftime('%Y-%m-%d %H:%M:%S')
    }

    return jsonify({
        'access_token': access_token,
        'data': user_data,
        'message': 'Login successful'
    }), 200

@app.route('/user', methods=['GET'])
@jwt_required()
def get_user():
    user_id = get_jwt_identity() 

    user = mongo.db.users.find_one({'_id': ObjectId(user_id)})
    if not user:
        return jsonify({'message': 'User not found'}), 404

    user_data = {
        'id': str(user['_id']),
        'username': user['username'],
        'email': user['email'],
        'created_at': user['created_at'].strftime('%Y-%m-%d %H:%M:%S')
    }

    return jsonify({'data': user_data, 'message': 'User fetched successfully'}), 200


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
