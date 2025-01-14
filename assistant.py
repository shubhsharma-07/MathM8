from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from dotenv import load_dotenv
import google.generativeai as genai
from PIL import Image
import os
import easyocr
import sqlite3
from datetime import timedelta, datetime
import stripe

# Load environment variables from .env
load_dotenv()

# Initialize Google Gemini API (securely using .env)
genai.configure(api_key=os.getenv("GOOGLE_GEMINI_API_KEY"))

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
app.config['UPLOAD_FOLDER'] = os.getenv("UPLOAD_FOLDER")
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Session settings
app.permanent_session_lifetime = timedelta(minutes=30)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False  # Set to True in production with HTTPS
)

# Stripe configuration (securely using .env)
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")



# Initialize EasyOCR Reader
reader = easyocr.Reader(['en'])

# Database setup
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Create the table if it does not exist
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL)''')
    # Check and add subscription_expiry column if it does not exist
    try:
        cursor.execute('ALTER TABLE users ADD COLUMN subscription_expiry DATE DEFAULT NULL')
    except sqlite3.OperationalError:
        # Column already exists
        pass
    conn.commit()
    conn.close()


def add_user(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def authenticate_user(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
    user = cursor.fetchone()
    conn.close()
    return user

def update_subscription(username, expiry_date):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET subscription_expiry = ? WHERE username = ?', (expiry_date, username))
    conn.commit()
    conn.close()

def check_subscription(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT subscription_expiry FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()
    if result and result[0]:
        expiry_date = datetime.strptime(result[0], '%Y-%m-%d')
        return expiry_date > datetime.now()
    return False

# Initialize database
init_db()

def math_solver_response(user_input):
    """Send the user's math query to Google Gemini and return the response."""
    prompt = f"""
    You are an advanced AI math assistant. Your task is to listen to math problems and provide detailed, step-by-step solutions using proper LaTeX for mathematical expressions.
    Ensure the response uses newlines where necessary for clarity and readability.
    Here is the math problem to solve: {user_input}
    """
    try:
        # Send request to Google Gemini API
        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content(prompt)

        # Access the first candidate's text
        if response and response.candidates:
            result = response.candidates[0].content.parts[0].text
            # Wrap math expressions in delimiters
            formatted_result = result.replace("\n", "<br>")  # Replace newlines with HTML line breaks
            return formatted_result
        else:
            return "Sorry, no solution could be generated."
    except Exception as e:
        print("Error communicating with Google Gemini API:", e)
        return "Sorry, I encountered an error while solving your math problem."

def extract_text_from_image(image_path):
    """Use EasyOCR to extract text from an uploaded image."""
    try:
        results = reader.readtext(image_path, detail=0)  # Extract text without bounding box details
        return " ".join(results).strip()
    except Exception as e:
        print("Error during OCR:", e)
        return ""

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            return render_template('register.html', error="Passwords do not match!")

        if not add_user(username, password):
            return render_template('register.html', error="Username already exists!")

        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not authenticate_user(username, password):
            return render_template('login.html', error="Invalid username or password!")

        session['user'] = username
        session.permanent = True  # Enable session expiration
        return redirect(url_for('chatbot'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/subscribe', methods=['GET', 'POST'])
def subscribe():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Create a Stripe Checkout Session
        session_data = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': 'Monthly Subscription',
                    },
                    'unit_amount': 300,  # $3.00 in cents
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url=url_for('subscription_success', _external=True),
            cancel_url=url_for('subscribe', _external=True),
        )
        return redirect(session_data.url)

    return render_template('subscribe.html')

@app.route('/subscription_success')
def subscription_success():
    if 'user' not in session:
        return redirect(url_for('login'))

    # Update subscription in the database (valid for 30 days)
    expiry_date = (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d')
    update_subscription(session['user'], expiry_date)

    return "Subscription successful! Your account is now active."

@app.route('/chatbot')
def chatbot():
    if 'user' not in session:
        return redirect(url_for('login'))

    if not check_subscription(session['user']):
        return redirect(url_for('subscribe'))

    return render_template('chatbot.html')

@app.route('/process_message', methods=['POST'])
def process_message():
    if 'user' not in session:
        return jsonify({"response": "Unauthorized access. Please log in first."}), 401

    data = request.get_json()
    user_input = data.get('message', '')
    if not user_input:
        return jsonify({"response": "Please provide a math problem."})

    response = math_solver_response(user_input)
    return jsonify({"response": response})

@app.route('/upload_image', methods=['POST'])
def upload_image():
    if 'user' not in session:
        return jsonify({"response": "Unauthorized access. Please log in first."}), 401

    if 'file' not in request.files:
        return jsonify({"response": "No file uploaded."})

    file = request.files['file']
    if file.filename == '':
        return jsonify({"response": "No file selected."})

    try:
        # Save the uploaded file
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)

        # Extract text from the image
        extracted_text = extract_text_from_image(file_path)
        if not extracted_text:
            return jsonify({"response": "Could not extract text from the image."})

        # Solve the extracted math problem
        response = math_solver_response(extracted_text)
        return jsonify({"response": response, "extracted_text": extracted_text})

    except Exception as e:
        print("Error handling uploaded image:", e)
        return jsonify({"response": "An error occurred while processing the image."})

if __name__ == "__main__":
    app.run(debug=True)
