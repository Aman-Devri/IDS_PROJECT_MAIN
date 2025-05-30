import os
import threading
import time
import pandas as pd
import joblib
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from werkzeug.utils import secure_filename
from functools import wraps
from models import db, User
from sniffer import start_sniffing, network_logs
from flask_socketio import SocketIO


# Flask app setup
app = Flask(__name__)
socketio = SocketIO(app)

app.secret_key = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
db.init_app(app)

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in to access this page.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Load ML model and encoders
model = joblib.load('model/ids_model.pkl')
le_protocol = joblib.load('model/le_protocol.pkl')
le_service = joblib.load('model/le_service.pkl')
le_flag = joblib.load('model/le_flag.pkl')

# ==== FCFS IDS Queue System ====
file_queue = []
queue_lock = threading.Lock()

def scan_file(filepath):
    df = pd.read_csv(filepath)
    features = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
                'logged_in', 'wrong_fragment', 'same_srv_count', 'same_srv_rate']
    results = []
    for idx, row in df.iterrows():
        try:
            sample = [
                int(row['duration']),
                le_protocol.transform([row['protocol_type']])[0],
                le_service.transform([row['service']])[0],
                le_flag.transform([row['flag']])[0],
                int(row['src_bytes']),
                int(row['dst_bytes']),
                int(row['logged_in']),
                int(row['wrong_fragment']),
                int(row['same_srv_count']),
                float(row['same_srv_rate'])
            ]
            pred = model.predict([sample])[0]
            results.append({'row': idx+1, 'attack': pred})
        except Exception as e:
            results.append({'row': idx+1, 'attack': f"Error: {str(e)}"})
    attacks = [r for r in results if r['attack'] != "normal" and not str(r['attack']).startswith("Error")]
    return results, attacks

def process_queue():
    while True:
        with queue_lock:
            for fileinfo in file_queue:
                if fileinfo['status'] == 'waiting':
                    fileinfo['status'] = 'processing'
                    try:
                        results, attacks = scan_file(fileinfo['filepath'])
                        fileinfo['results'] = results
                        fileinfo['attacks'] = attacks
                        fileinfo['status'] = 'done'
                    except Exception as e:
                        fileinfo['results'] = []
                        fileinfo['attacks'] = [{'row': 0, 'attack': f"Error: {str(e)}"}]
                        fileinfo['status'] = 'done'
                    break
        time.sleep(1)

threading.Thread(target=process_queue, daemon=True).start()

# ==== NIDS Routes ====

@app.route('/nids')
@login_required
def nids_dashboard():
    print(f"Current logs count: {len(network_logs)}")
    return render_template('network_logs.html', logs=network_logs)

# ... your existing imports and setup ...

# Existing ML model and encoders loading stays as-is
model = joblib.load('model/ids_model.pkl')
le_protocol = joblib.load('model/le_protocol.pkl')
le_service = joblib.load('model/le_service.pkl')
le_flag = joblib.load('model/le_flag.pkl')

# === Modify /start_monitoring route ===
@app.route('/start_monitoring')
@login_required
def start_monitoring():
    # Start the sniffing thread with socketio and model params
    thread = threading.Thread(
        target=start_sniffing,
        args=(socketio, model, le_protocol, le_service, le_flag)
    )
    thread.daemon = True
    thread.start()
    flash("✅ Network monitoring started.")
    return redirect(url_for('nids_dashboard'))

# Optional: SocketIO connection event (helps track active clients)
@socketio.on('connect')
def handle_connect():
    print(f"[SocketIO] Client connected: {request.sid}")
    # Optionally emit a welcome message or initial data
    socketio.emit('message', {'msg': 'Welcome to IDS Network Monitor!'})

# Optional: SocketIO disconnect event
@socketio.on('disconnect')
def handle_disconnect():
    print(f"[SocketIO] Client disconnected: {request.sid}")

@app.route('/network_logs')
@login_required
def show_network_logs():
    return render_template('network_logs.html', logs=network_logs)

# ==== Auth Routes ====

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        if User.query.filter_by(username=username).first():
            flash("Username already exists!")
            return redirect(url_for('signup'))
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Account created. Please login.')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['username'] = username
            flash('Logged in successfully!')
            return redirect(url_for('index'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    flash('Logged out.')
    return render_template('logout.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        user = User.query.filter_by(username=username).first()
        if user:
            flash(f"Password reset link sent to {user.email}. (Simulated)")
        else:
            flash("Username not found!")
    return render_template('forgot_password.html')

# ==== UI Routes ====

@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        file = request.files.get('file')
        if not file or file.filename == '':
            flash('No file selected')
            return redirect(request.url)
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        with queue_lock:
            file_queue.append({
                'filename': filename,
                'filepath': filepath,
                'status': 'waiting',
                'results': [],
                'attacks': []
            })
        flash(f'File {filename} uploaded and queued.')
        return redirect(url_for('queue_status'))
    return render_template('upload.html')

@app.route('/queue')
@login_required
def queue_status():
    with queue_lock:
        queue_snapshot = list(file_queue)
    return render_template('queue.html', file_queue=queue_snapshot)

@app.route('/delete/<filename>', methods=['POST'])
@login_required
def delete_file(filename):
    deleted = False
    with queue_lock:
        for i, f in enumerate(file_queue):
            if f['filename'] == filename:
                if os.path.exists(f['filepath']):
                    os.remove(f['filepath'])
                del file_queue[i]
                deleted = True
                flash(f'File {filename} deleted.')
                break
    if not deleted:
        flash('File not found.')
    return redirect(url_for('queue_status'))

@app.route('/download/<filename>')
@login_required
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/team')
@login_required
def team():
    return render_template('team.html')

@app.route('/simulate_traffic', methods=['POST'])
@login_required
def simulate_traffic():
    data = request.form
    try:
        features = [
            int(data['duration']),
            le_protocol.transform([data['protocol_type']])[0],
            le_service.transform([data['service']])[0],
            le_flag.transform([data['flag']])[0],
            int(data['src_bytes']),
            int(data['dst_bytes']),
            int(data['logged_in']),
            int(data['wrong_fragment']),
            int(data['same_srv_count']),
            float(data['same_srv_rate'])
        ]
        pred = model.predict([features])[0]
    except Exception as e:
        pred = f"Error: {str(e)}"
    return render_template('index.html', prediction=pred)

# ==== App Bootstrap ====

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True)

