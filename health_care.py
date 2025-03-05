from flask import Flask, jsonify, request, render_template
import psycopg2  # pip install psycopg2
from psycopg2 import sql
from flask_bcrypt import Bcrypt  # pip install flask-bcrypt
import jwt  # pip install pyjwt
import datetime

app = Flask(__name__)

# Database connection configuration
DB_HOST = 'localhost'
DB_NAME = 'healthcare_db'
DB_USER = 'postgres'
DB_PASSWORD = 'postgres'

# Secret key for signing JWT tokens
SECRET_KEY = "super_secure_secret_key"

# Initialize bcrypt for password hashing
bcrypt = Bcrypt()

# Function to connect to PostgreSQL database
def get_db_connection():
    return psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )

# Create necessary tables if they do not exist
def initialize_db():
    connection = get_db_connection()
    cursor = connection.cursor()

    # Create Users Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL  -- Patient, Doctor, Admin
        );
    """)

    # Create Patients Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS patients (
            patient_id SERIAL PRIMARY KEY,
            user_id INT REFERENCES users(user_id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            age INT NOT NULL,
            medical_history TEXT
        );
    """)

    # Create Doctors Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS doctors (
            doctor_id SERIAL PRIMARY KEY,
            user_id INT REFERENCES users(user_id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            specialization TEXT NOT NULL
        );
    """)

    # Create Appointments Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS appointments (
            appointment_id SERIAL PRIMARY KEY,
            patient_id INT REFERENCES patients(patient_id) ON DELETE CASCADE,
            doctor_id INT REFERENCES doctors(doctor_id) ON DELETE CASCADE,
            appointment_date TIMESTAMP NOT NULL
        );
    """)

    connection.commit()
    cursor.close()
    connection.close()

# Initialize the database tables
initialize_db()

# Function to encode a password
def encode_password(password):
    return bcrypt.generate_password_hash(password).decode('utf-8')

# Function to check a hashed password
def check_password(hashed_password, password):
    return bcrypt.check_password_hash(hashed_password, password)

# Function to decode a JWT token
def decode_token(jwt_token):
    try:
        return jwt.decode(jwt_token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired!"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token!"}), 401

# ✅ Register a New User
@app.route('/register', methods=['POST'])
def register_user():
    data = request.json
    username = data['username']
    password = encode_password(data['password'])
    role = data['role']  # "Patient", "Doctor", or "Admin"

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO users (username, password, role) VALUES (%s, %s, %s) RETURNING user_id;
    """, (username, password, role))

    user_id = cursor.fetchone()[0]
    
    connection.commit()
    cursor.close()
    connection.close()

    return jsonify({"message": "User registered successfully.", "user_id": user_id}), 201

# ✅ User Login (JWT Authentication)
@app.route('/login', methods=['POST'])
def login_user():
    data = request.json
    username = data['username']
    password = data['password']

    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE username = %s;", (username,))
    user = cursor.fetchone()

    if user and check_password(user[2], password):
        payload = {
            'user_id': user[0],
            'role': user[3],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

        return jsonify({"message": "Login successful.", "token": token}), 200

    return jsonify({"message": "Invalid username or password."}), 401

# ✅ Add Patient Profile (Only for Patients)
@app.route('/add-patient', methods=['POST'])
def add_patient():
    data = request.json
    jwt_token = request.headers.get('Authorization')
    decoded_token = decode_token(jwt_token)
    
    if decoded_token['role'] != "Patient":
        return jsonify({"message": "Unauthorized"}), 403

    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
        INSERT INTO patients (user_id, name, age, medical_history) VALUES (%s, %s, %s, %s);
    """, (decoded_token['user_id'], data['name'], data['age'], data['medical_history']))

    connection.commit()
    cursor.close()
    connection.close()
    return jsonify({"message": "Patient profile created successfully."}), 201

# ✅ Add Doctor Profile (Only for Doctors)
@app.route('/add-doctor', methods=['POST'])
def add_doctor():
    data = request.json
    jwt_token = request.headers.get('Authorization')
    decoded_token = decode_token(jwt_token)
    
    if decoded_token['role'] != "Doctor":
        return jsonify({"message": "Unauthorized"}), 403

    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
        INSERT INTO doctors (user_id, name, specialization) VALUES (%s, %s, %s);
    """, (decoded_token['user_id'], data['name'], data['specialization']))

    connection.commit()
    cursor.close()
    connection.close()
    return jsonify({"message": "Doctor profile created successfully."}), 201

# ✅ Book an Appointment (Only for Patients)
@app.route('/book-appointment', methods=['POST'])
def book_appointment():
    data = request.json
    jwt_token = request.headers.get('Authorization')
    decoded_token = decode_token(jwt_token)

    if decoded_token['role'] != "Patient":
        return jsonify({"message": "Unauthorized"}), 403

    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
        INSERT INTO appointments (patient_id, doctor_id, appointment_date) VALUES (
            (SELECT patient_id FROM patients WHERE user_id = %s), %s, %s
        );
    """, (decoded_token['user_id'], data['doctor_id'], data['appointment_date']))

    connection.commit()
    cursor.close()
    connection.close()
    return jsonify({"message": "Appointment booked successfully."}), 201

# ✅ View Appointments (Only for Doctors)
@app.route('/view-appointments', methods=['GET'])
def view_appointments():
    jwt_token = request.headers.get('Authorization')
    decoded_token = decode_token(jwt_token)

    if decoded_token['role'] != "Doctor":
        return jsonify({"message": "Unauthorized"}), 403

    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
        SELECT * FROM appointments WHERE doctor_id = (
            SELECT doctor_id FROM doctors WHERE user_id = %s
        );
    """, (decoded_token['user_id'],))

    appointments = cursor.fetchall()
    return jsonify(appointments), 200

if __name__ == '__main__':
    app.run(debug=True)
