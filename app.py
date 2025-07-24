from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, smtplib, random, os, pandas as pd, requests
from email.message import EmailMessage
from flask_cors import CORS
from dotenv import load_dotenv
from sqlalchemy import inspect

# Load env vars
load_dotenv()
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

app = Flask(__name__)
app.secret_key = "your-secret-key"
CORS(app)

# ------------------ DB INIT ------------------
def init_db():
    with sqlite3.connect("users.db") as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                username TEXT UNIQUE,
                password TEXT,
                email TEXT
            )
        ''')

        conn.execute('''
            CREATE TABLE IF NOT EXISTS saved_colleges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                college_name TEXT,
                state TEXT,
                stream TEXT,
                rank INTEGER,
                tlr REAL,
                placement REAL,
                perception REAL
            )
        ''')

        conn.execute('''
            CREATE TABLE IF NOT EXISTS saved_colleges_dashboard (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                college_name TEXT,
                state TEXT,
                stream TEXT,
                rating REAL,
                academic REAL,
                accommodation REAL,
                faculty REAL,
                infrastructure REAL,
                placement REAL,
                social_life REAL
            )
        ''')


# ------------------ FORMS ------------------
class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class SignupForm(FlaskForm):
    name = StringField("Full Name", validators=[DataRequired()])
    username = StringField("Username", validators=[DataRequired(), Length(min=4)])
    password = PasswordField("Password", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    submit = SubmitField("Signup")

# ------------------ EMAIL OTP ------------------
def send_otp_email(receiver_email, otp):
    msg = EmailMessage()
    msg.set_content(f"Your OTP for Udaan Path is: {otp}")
    msg['Subject'] = "OTP Verification"
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = receiver_email

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
        return True
    except Exception as e:
        print("Email failed:", e)
        return False

# ------------------ ROUTES ------------------

@app.route("/")
def home():
    return redirect("/login")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        otp = str(random.randint(1000, 9999))
        session['otp'] = otp
        session['temp_user'] = {
            "name": form.name.data.strip(),
            "username": form.username.data.strip(),
            "password": generate_password_hash(form.password.data.strip()),
            "email": form.email.data.strip()
        }
        if send_otp_email(form.email.data.strip(), otp):
            return redirect("/verify-otp")
        else:
            flash("❌ Failed to send OTP.", "danger")
    return render_template("signup.html", form=form)

@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if request.method == "GET" and not session.get("temp_user"):
        return redirect("/signup")

    if request.method == "POST":
        if request.form.get("otp") == session.get("otp"):
            user = session.get("temp_user")
            try:
                with sqlite3.connect("users.db") as conn:
                    conn.execute("INSERT INTO users (name, username, password, email) VALUES (?, ?, ?, ?)",
                                 (user["name"], user["username"], user["password"], user["email"]))
                session.pop("temp_user")
                session.pop("otp")
                session['name'] = user['name']
                session['user'] = user['username']
                flash("✅ Signup successful.", "success")
                return redirect("/login")
            except sqlite3.IntegrityError:
                flash("Username exists.", "danger")
        else:
            flash("❌ Wrong OTP.", "danger")
    return render_template("verify_otp.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        with sqlite3.connect("users.db") as conn:
            row = conn.execute("SELECT id, password, name FROM users WHERE username = ?", (form.username.data,)).fetchone()
            if row and check_password_hash(row[1], form.password.data):
                session['user'] = form.username.data
                session['user_id'] = row[0]
                session['name'] = row[2]
                return redirect("/dashboard")
            else:
                flash("❌ Invalid credentials", "danger")
    return render_template("login.html", form=form)

@app.route('/dashboard', methods=['GET'])
def dashboard():
    return render_template('dashboard.html')

df = pd.read_csv('data/unique_colleges.csv')

@app.route('/get-colleges', methods=['POST'])
def get_colleges():
    stream = request.form['stream']
    state = request.form['location']

    filtered = df[
        (df['Stream'].str.lower() == stream.lower()) &
        (df['State'].str.lower() == state.lower())
    ]

    display_cols = ['College_Name', 'State', 'Stream', 'Rating', 'Academic', 
                    'Accommodation', 'Faculty', 'Infrastructure', 'Placement', 'Social_Life']
    
    colleges = filtered[display_cols].to_dict(orient='records')

    return render_template('results.html', colleges=colleges, state=state, stream=stream)

@app.route("/chatbot", methods=['POST'])
def chatbot():
    user_input = request.json.get('message', '')
    if not user_input:
        return jsonify({'response': "Please enter a message."})

    try:
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": "llama3-8b-8192",
                "messages": [
                    {"role": "system", "content": "You are a helpful, professional academic and career mentor for students."},
                    {"role": "user", "content": user_input}
                ],
                "temperature": 0.7,
                "max_tokens": 100 
            },
            timeout=30
        )
        data = response.json()
        return jsonify({'response': data['choices'][0]['message']['content']})
    except Exception as e:
        return jsonify({'response': f"Error: {str(e)}"})

@app.route('/top-colleges', methods=['GET'])
def top_colleges_form():
    return render_template('top_colleges.html')

@app.route('/top-colleges-results', methods=['POST'])
def top_colleges_results():
    stream = request.form.get('stream')
    state = request.form.get('state')
    sort_by = request.form.get('sort_by', 'rank')  

    df = pd.read_csv('data/top_colleges.csv')
    filtered = df[df['Stream'].str.lower() == stream.lower()]

    if state:
        filtered = filtered[filtered['state'].str.lower() == state.lower()]
    if sort_by in ['rank', 'tlr', 'go', 'perception']:
        filtered = filtered.sort_values(by=sort_by, ascending=True if sort_by == 'rank' else False)
    top_filtered = filtered.head(20)
    return render_template('top_colleges_results.html', colleges=top_filtered)

@app.route('/saved-colleges-dashboard')
def saved_colleges_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        SELECT college_name, state, stream, rating, academic, accommodation, faculty,
               infrastructure, placement, social_life
        FROM saved_colleges_dashboard
        WHERE user_id = ?
    ''', (user_id,))
    colleges = c.fetchall()
    conn.close()

    return render_template('saved_colleges_dashboard.html', colleges=colleges)

@app.route('/save-college-dashboard', methods=['POST'])
def save_college_dashboard():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    data = request.get_json()
    user_id = session['user_id']

    name = data.get('college_name')
    state = data.get('state')
    stream = data.get('stream')
    rating = data.get('rating')
    academic = data.get('academic')
    accommodation = data.get('accommodation')
    faculty = data.get('faculty')
    infrastructure = data.get('infrastructure')
    placement = data.get('placement')
    social_life = data.get('social_life')

    if not all([name, state, stream]):
        return jsonify({'error': 'Missing required fields'}), 400

    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    c.execute("""
        SELECT 1 FROM saved_colleges_dashboard
        WHERE user_id = ? AND college_name = ?
    """, (user_id, name))
    if c.fetchone() is None:
        c.execute("""
            INSERT INTO saved_colleges_dashboard (
                user_id, college_name, state, stream,
                rating, academic, accommodation, faculty,
                infrastructure, placement, social_life
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id, name, state, stream, rating, academic, accommodation,
            faculty, infrastructure, placement, social_life
        ))
        conn.commit()

    conn.close()
    return jsonify({'success': True})

@app.route('/delete-dashboard-college', methods=['POST'])
def delete_dashboard_college():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    college_name = request.form.get('college_name')
    user_id = session['user_id']

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('DELETE FROM saved_colleges_dashboard WHERE user_id = ? AND college_name = ?', (user_id, college_name))
    conn.commit()
    conn.close()

    return redirect(url_for('saved_colleges_dashboard'))

@app.route('/save-college', methods=['POST'])
def save_college():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    user_id = session['user_id']
    data = request.get_json()

    name = data.get('college_name')
    state = data.get('state')
    stream = data.get('stream')
    rank = data.get('rank')
    tlr = data.get('tlr')
    placement = data.get('placement')
    perception = data.get('perception')

    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    c.execute("""
        SELECT * FROM saved_colleges WHERE user_id=? AND college_name=?
    """, (user_id, name))
    if c.fetchone() is None:
        c.execute("""
            INSERT INTO saved_colleges (user_id, college_name, state, stream, rank, tlr, placement, perception)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, name, state, stream, rank, tlr, placement, perception))
        conn.commit()

    conn.close()

    return jsonify({'success': True})

@app.route('/saved-colleges')
def saved_colleges():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        SELECT college_name, state, stream, rank, tlr, placement, perception
        FROM saved_colleges
        WHERE user_id = ?
    ''', (session['user_id'],))
    colleges = c.fetchall()
    conn.close()

    return render_template('saved_colleges.html', colleges=colleges)

@app.route('/delete-college', methods=['POST'])
def delete_college():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    college_name = request.form.get('college_name')
    user_id = session['user_id']

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('DELETE FROM saved_colleges WHERE user_id = ? AND college_name = ?', (user_id, college_name))
    conn.commit()
    conn.close()

    return redirect(url_for('saved_colleges'))

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect("/login")


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
