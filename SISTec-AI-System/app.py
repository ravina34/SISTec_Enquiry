import os
import logging
from flask import Flask, request, jsonify, session, render_template, redirect, url_for
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, text

# agents/logic.py se chat logic import karein
from agents.logic import generate_chatbot_response

# ---------------------------------------
# Flask App Setup
# ---------------------------------------

logging.basicConfig(level=logging.INFO)

app = Flask(__name__) 
# NOTE: Secret key production ke liye badalna zaroori hai
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'secure_key_for_sistec_ai') 
CORS(app)

# ---------------------------------------
# Database Setup and Admin Config
# ---------------------------------------

DATABASE_URL = os.environ.get("DATABASE_URL")
engine = None

# Admin Credentials (For initial setup and hardcoded check)
ADMIN_EMAIL = "admin@sistec.in" 
ADMIN_PASSWORD_HASH = generate_password_hash("superadmin") 

if DATABASE_URL:
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace(
            "postgres://",
            "postgresql+psycopg://",
            1
        )
    try:
        engine = create_engine(DATABASE_URL)
        logging.info("Database engine created successfully.")
    except Exception as e:
        logging.error(f"Error creating engine: {e}")
else:
    logging.error("DATABASE_URL is not set.")


def setup_db():
    if not engine:
        logging.error("Cannot set up DB: Engine is None.")
        return

    try:
        with engine.begin() as conn:
            # 1. ENUM Type (Ensures query_status exists for the queries table)
            conn.execute(text("""
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'query_status') THEN
                        CREATE TYPE query_status AS ENUM ('pending', 'unanswered', 'answered');
                    END IF;
                END$$;
            """))
            
            # 2. Users Table (Main authentication table)
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id SERIAL PRIMARY KEY,
                    full_name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    mobile TEXT,
                    password TEXT NOT NULL, -- Matches final SQL schema
                    address TEXT,
                    user_role VARCHAR(10) NOT NULL DEFAULT 'student',
                    created_at TIMESTAMP DEFAULT NOW()
                );
            """))

            # 3. Chat History Table (For bot interactions)
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS chat_history (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
                    query_text TEXT NOT NULL, 
                    response_text TEXT NOT NULL, 
                    timestamp TIMESTAMP DEFAULT NOW()
                );
            """))

            # 4. Queries Table (For user-submitted queries/tickets)
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS queries (
                    query_id SERIAL PRIMARY KEY,
                    user_id INT REFERENCES users(user_id) ON DELETE CASCADE,
                    query_text TEXT NOT NULL,
                    status query_status DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT NOW()
                );
            """))

            # 5. Query Responses Table (For admin responses to queries/tickets)
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS query_responses (
                    response_id SERIAL PRIMARY KEY,
                    query_id INT REFERENCES queries(query_id) ON DELETE CASCADE,
                    response_text TEXT NOT NULL,
                    response_time TIMESTAMP DEFAULT NOW()
                );
            """))
            
            # 6. Auto-insert/update the default Admin user
            conn.execute(text("""
                INSERT INTO users (full_name, email, password, user_role)
                VALUES (:name, :email, :password_hash, 'admin')
                ON CONFLICT (email) DO UPDATE SET 
                    user_role = 'admin', 
                    password = :password_hash, -- Uses 'password' column
                    full_name = :name;
            """), {
                "name": "System Admin",
                "email": ADMIN_EMAIL,
                "password_hash": ADMIN_PASSWORD_HASH
            })

        logging.info("Database tables created or verified and admin user ensured.")
    except Exception as e:
        logging.error(f"Database setup error: {e}")


# Run DB setup
with app.app_context():
    if engine:
        setup_db()
    else:
        logging.error("Database engine failed to initialize. Check DATABASE_URL.")


def get_user_id_from_session():
    return session.get("user_id")

def is_admin_logged_in():
    return session.get("is_admin") == True

def save_chat_entry(user_id, query, response):
    if not engine:
        return

    try:
        with engine.begin() as connection:
            connection.execute(text("""
                INSERT INTO chat_history (user_id, query_text, response_text)
                VALUES (:user_id, :query, :response)
            """), {
                "user_id": user_id,
                "query": query,
                "response": response
            })
    except Exception as e:
        logging.error(f"Error saving chat history: {e}")


# ---------------------------------------
# Frontend Routes (GET Requests)
# ---------------------------------------

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/login')
def login_page():
    return render_template('st_login.html')

@app.route('/admin/login')
def admin_login_page():
    return render_template('ad_login.html')

@app.route('/admin/dashboard')
def admin_dashboard_page():
    if not is_admin_logged_in():
        return redirect(url_for('admin_login_page'))
    
    try:
        if engine:
            with engine.connect() as connection:
                # Count only 'student' roles
                total_students = connection.execute(text("SELECT COUNT(*) FROM users WHERE user_role = 'student'")).scalar()
                total_chats = connection.execute(text("SELECT COUNT(*) FROM chat_history")).scalar()
                
                # Fetch recent chats for display
                recent_chats = connection.execute(text("""
                    SELECT u.full_name, c.query_text, c.response_text, c.timestamp
                    FROM chat_history c
                    JOIN users u ON c.user_id = u.user_id
                    ORDER BY c.timestamp DESC
                    LIMIT 5
                """)).fetchall()
                
                recent_chats_list = [
                    {
                        "name": r[0], 
                        "query": r[1][:50] + "..." if len(r[1]) > 50 else r[1],
                        "response": r[2][:70] + "..." if len(r[2]) > 70 else r[2],
                        "timestamp": r[3].strftime("%Y-%m-%d %H:%M:%S")
                    } for r in recent_chats
                ]

        return render_template(
            'ad_dash.html', 
            admin_name=session.get('user_name', 'Admin User'),
            total_students=total_students if engine else "N/A",
            total_chats=total_chats if engine else "N/A",
            recent_chats=recent_chats_list if engine else []
        )
    except Exception as e:
        logging.error(f"Error fetching admin dashboard data: {e}")
        return render_template('ad_dash.html', 
            admin_name="Admin User", 
            total_students="Error", 
            total_chats="Error",
            recent_chats=[]
        )


@app.route('/user')
def user_dashboard():
    if "user_id" not in session:
        return redirect(url_for('login_page'))
        
    user_name = session.get('user_name', 'Student')
    return render_template('st_dashboard.html', user_name=user_name)


# ---------------------------------------
# Auth Routes (POST Requests)
# ---------------------------------------

@app.route('/register', methods=['POST'])
def register():
    if not engine:
        return jsonify({"message": "Database Error"}), 500

    try:
        data = request.form
        full_name = data['name']
        mobile = data['mobile']
        email = data['email']
        password = data['password']
        address = data.get('address', '')

        password_hash = generate_password_hash(password)

        with engine.begin() as connection:
            exists = connection.execute(text("""
                SELECT user_id FROM users WHERE email = :email OR mobile = :mobile
            """), {"email": email, "mobile": mobile}).fetchone()

            if exists:
                return jsonify({"message": "Email or Mobile already exists"}), 409

            # Using 'password' column name in SQL
            connection.execute(text("""
                INSERT INTO users (full_name, mobile, email, address, password, user_role)
                VALUES (:full_name, :mobile, :email, :address, :password, 'student')
            """), {
                "full_name": full_name,
                "mobile": mobile,
                "email": email,
                "address": address,
                "password": password_hash # variable name is fine, column name is 'password'
            })

        return jsonify({"message": "Registration successful"}), 201

    except Exception as e:
        logging.error(f"Register error: {e}")
        return jsonify({"message": "Server Error during registration"}), 500


@app.route('/login', methods=['POST'])
def login():
    if not engine:
        return jsonify({"message": "Database Error"}), 500

    try:
        data = request.form
        email = data['email']
        password = data['password']

        with engine.connect() as connection:
            # Using 'password' column name in SQL
            user = connection.execute(text("""
                SELECT user_id, full_name, password, user_role FROM users WHERE email = :email AND user_role = 'student'
            """), {"email": email}).fetchone()

            if user and check_password_hash(user[2], password):
                session['user_id'] = user[0]
                session['user_name'] = user[1]
                session.pop('is_admin', None) 
                return jsonify({"message": "Login successful", "redirect_url": "/user"}), 200
            else:
                return jsonify({"message": "Invalid email or password for student login"}), 401

    except Exception as e:
        logging.error(f"Login error: {e}")
        return jsonify({"message": "Server Error during student login"}), 500


@app.route('/admin/login', methods=['POST'])
def admin_login():
    if not engine:
        return jsonify({"message": "Database Error"}), 500
        
    data = request.form
    email = data.get('email')
    password = data.get('password')

    try:
        with engine.connect() as connection:
            # Using 'password' column name in SQL
            admin_user = connection.execute(text("""
                SELECT user_id, full_name, password FROM users 
                WHERE email = :email AND user_role = 'admin'
            """), {"email": email}).fetchone()

            if admin_user and check_password_hash(admin_user[2], password):
                session['is_admin'] = True
                session['user_id'] = admin_user[0]
                session['user_name'] = admin_user[1]
                return jsonify({"message": "Admin login successful", "redirect_url": "/admin/dashboard"}), 200
            else:
                return jsonify({"message": "Invalid admin credentials"}), 401
    except Exception as e:
        logging.error(f"Admin Login error: {e}")
        return jsonify({"message": "Server Error during admin login"}), 500


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"message": "Logged out"}), 200


# ---------------------------------------
# Chat API Route
# ---------------------------------------

@app.route('/chat', methods=['POST'])
def chat():
    user_id = get_user_id_from_session()
    if not user_id:
        return jsonify({"response": "Please log in first"}), 401

    try:
        data = request.json
        user_query = data.get("query")

        if not user_query:
            return jsonify({"response": "Query cannot be empty"}), 400

        # generate_chatbot_response is now more robust against API response changes
        bot_response, sources = generate_chatbot_response(user_query)

        final_response_text = bot_response

        if sources:
            source_text = "\n\n**Sources:**\n"
            for i, source in enumerate(sources):
                uri = source['uri'].replace('(', '%28').replace(')', '%29')
                source_text += f"{i+1}. [{source['title']}]({uri})\n"
            final_response_text += source_text
        
        save_chat_entry(user_id, user_query, final_response_text)

        # The chat route now returns the generated response successfully
        # The 200 status code indicates that the request was processed, even if the response
        # is an error message (handled inside generate_chatbot_response).
        return jsonify({"response": final_response_text}), 200

    except Exception as e:
        logging.error(f"Chat route error: {e}")
        return jsonify({"response": "Server Error: Could not process query."}), 500


# ---------------------------------------
# Run App
# ---------------------------------------

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))