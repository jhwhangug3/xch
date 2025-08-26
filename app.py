from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import hashlib
import secrets
import threading
import time
from cryptography.fernet import Fernet
import base64

app = Flask(__name__)
# Use stable secret from env if provided to persist sessions across restarts
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=180)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = bool(os.environ.get('SESSION_COOKIE_SECURE', '1') == '1')
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB limit
ALLOWED_EXTENSIONS = { 'png', 'jpg', 'jpeg', 'gif', 'webp' }

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route('/favicon.ico')
def favicon():
    return redirect(url_for('static', filename='images/fav.png'))

# Database configuration: Prefer env var, fallback to provided Render Postgres URL
_default_postgres_url = (
    'postgresql+psycopg://database_db_81rr_user:'
    'N5xaJ1T1sZ1SwnaQYHS8JheZGt0qZpsm'
    '@dpg-d2m7qimr433s73cqvdg0-a.singapore-postgres.render.com/database_db_81rr'
)
_database_url = os.environ.get('DATABASE_URL', _default_postgres_url)
# Ensure SSL for Render Postgres
if 'sslmode=' not in _database_url:
    connector = '&' if '?' in _database_url else '?'
    _database_url = f"{_database_url}{connector}sslmode=require"

# Single database for all tables
app.config['SQLALCHEMY_DATABASE_URI'] = _database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
    'pool_size': 10,
    'max_overflow': 20
}

db = SQLAlchemy(app)

# Global encryption key for message encryption
ENCRYPTION_KEY = Fernet.generate_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

# Ultra-fast message cache with threading
message_cache = {}
cache_lock = threading.Lock()
user_sessions = {}
session_lock = threading.Lock()
# (Legacy in-memory kept but unused for Render reliability)
typing_status = {}
typing_lock = threading.Lock()
_read_receipts = {}
read_receipts_lock = threading.Lock()

# Helper: normalize typing key consistently as strings
def _typing_key(chat_session_id, user_id):
    return (str(chat_session_id), str(user_id))

# Enhanced Database Models with optimized structure
class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(200), nullable=False)
    first_name = db.Column(db.String(50), index=True)
    last_name = db.Column(db.String(50), index=True)
    email = db.Column(db.String(120), unique=True, nullable=True, index=True)
    bio = db.Column(db.Text)
    profile_picture = db.Column(db.String(200))
    is_online = db.Column(db.Boolean, default=False, index=True)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    public_key = db.Column(db.Text, index=True)  # For E2E encryption
    private_key_encrypted = db.Column(db.Text)  # Encrypted private key
    is_active = db.Column(db.Boolean, default=True, index=True)
    last_login = db.Column(db.DateTime)
    
    # Relationships
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy='dynamic')
    received_messages = db.relationship('Message', foreign_keys='Message.receiver_id', backref='receiver', lazy='dynamic')
    sent_friend_requests = db.relationship('FriendRequest', foreign_keys='FriendRequest.sender_id', backref='sender', lazy=True)
    received_friend_requests = db.relationship('FriendRequest', foreign_keys='FriendRequest.receiver_id', backref='receiver', lazy=True)
    friendships = db.relationship('Friendship', foreign_keys='Friendship.user_id', backref='user', lazy=True)
    profile = db.relationship('UserProfile', backref='user', uselist=False, lazy=True)
    
    def generate_keys(self):
        """Generate E2E encryption keys for user"""
        # Simplified key generation for now
        private_key = Fernet.generate_key()
        public_key = base64.urlsafe_b64encode(private_key).decode()
        
        self.public_key = public_key
        self.private_key_encrypted = cipher_suite.encrypt(private_key).decode()
        return public_key, private_key
    
    def to_dict(self):
        """Convert user to dictionary for JSON responses"""
        return {
            'id': self.id,
            'username': self.username,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'bio': self.bio,
            'profile_picture': self.profile_picture,
            'is_online': self.is_online,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'public_key': self.public_key
        }

class UserProfile(db.Model):
    __tablename__ = 'user_profiles'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), unique=True, nullable=False, index=True)
    display_name = db.Column(db.String(100), index=True)
    bio = db.Column(db.Text)
    profile_picture = db.Column(db.String(200))
    theme_preference = db.Column(db.String(20), default='light', index=True)
    notification_settings = db.Column(db.Text)  # JSON string
    privacy_settings = db.Column(db.Text)  # JSON string
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    timezone = db.Column(db.String(50), default='UTC')
    language = db.Column(db.String(10), default='en')
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'display_name': self.display_name,
            'bio': self.bio,
            'profile_picture': self.profile_picture,
            'theme_preference': self.theme_preference,
            'timezone': self.timezone,
            'language': self.language
        }

class FriendRequest(db.Model):
    __tablename__ = 'friend_requests'
    
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    status = db.Column(db.String(20), default='pending', index=True)  # pending, accepted, rejected
    message = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Composite unique constraint
    __table_args__ = (db.UniqueConstraint('sender_id', 'receiver_id', name='unique_friend_request'),)

class Friendship(db.Model):
    __tablename__ = 'friendships'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    friend_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    chat_session_id = db.Column(db.String(64), unique=True, index=True)  # Unique chat session
    last_message_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    unread_count = db.Column(db.Integer, default=0, index=True)
    
    # Composite unique constraint
    __table_args__ = (db.UniqueConstraint('user_id', 'friend_id', name='unique_friendship'),)
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Generate unique chat session ID
        self.chat_session_id = hashlib.sha256(
            f"{min(self.user_id, self.friend_id)}_{max(self.user_id, self.friend_id)}_{time.time()}".encode()
        ).hexdigest()

# Chat Database Models (now in single database)
class Message(db.Model):
    __tablename__ = 'messages'
    
    id = db.Column(db.Integer, primary_key=True)
    chat_session_id = db.Column(db.String(64), nullable=False, index=True)  # Link to friendship
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    content = db.Column(db.Text, nullable=False)  # Plain text content for now
    content_hash = db.Column(db.String(64), nullable=False)  # Hash for integrity
    message_type = db.Column(db.String(20), default='text', index=True)  # text, image, file, system
    is_read = db.Column(db.Boolean, default=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    encryption_version = db.Column(db.String(10), default='v1')
    reply_to_id = db.Column(db.Integer, db.ForeignKey('messages.id'), nullable=True)  # For replies
    edited_at = db.Column(db.DateTime, nullable=True)
    deleted_at = db.Column(db.DateTime, nullable=True)
    
    # Indexes for better performance
    __table_args__ = (
        db.Index('idx_chat_session_timestamp', 'chat_session_id', 'timestamp'),
        db.Index('idx_sender_receiver', 'sender_id', 'receiver_id'),
        db.Index('idx_unread_messages', 'receiver_id', 'is_read', 'timestamp'),
    )
    
    def to_dict(self):
        """Convert message to dictionary for JSON responses"""
        return {
            'id': self.id,
            'chat_session_id': self.chat_session_id,
            'sender_id': self.sender_id,
            'receiver_id': self.receiver_id,
            'content': self.content,
            'content_hash': self.content_hash,
            'message_type': self.message_type,
            'is_read': self.is_read,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'reply_to_id': self.reply_to_id,
            'edited_at': self.edited_at.isoformat() if self.edited_at else None
        }

class ChatSession(db.Model):
    __tablename__ = 'chat_sessions'
    
    id = db.Column(db.String(64), primary_key=True)  # Same as friendship.chat_session_id
    user1_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    user2_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    last_message_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    last_message_id = db.Column(db.Integer, db.ForeignKey('messages.id'), nullable=True)
    unread_count_user1 = db.Column(db.Integer, default=0, index=True)
    unread_count_user2 = db.Column(db.Integer, default=0, index=True)
    is_active = db.Column(db.Boolean, default=True, index=True)
    
    # Indexes for better performance
    __table_args__ = (
        db.Index('idx_users_session', 'user1_id', 'user2_id'),
        db.Index('idx_last_message', 'last_message_at'),
    )

class MessageReaction(db.Model):
    __tablename__ = 'message_reactions'
    
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('messages.id', ondelete='CASCADE'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    reaction_type = db.Column(db.String(20), nullable=False, index=True)  # like, love, laugh, etc.
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Composite unique constraint
    __table_args__ = (db.UniqueConstraint('message_id', 'user_id', 'reaction_type', name='unique_reaction'),)

class TypingStatus(db.Model):
    __tablename__ = 'typing_status'
    chat_session_id = db.Column(db.String(64), primary_key=True)
    user_id = db.Column(db.Integer, primary_key=True)
    last_typing_at = db.Column(db.DateTime, index=True, nullable=False, default=datetime.utcnow)

# Routes
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip().lower()
        password = request.form['password']
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        email = request.form.get('email', '').strip()
        
        # Enhanced validation
        if len(username) < 3:
            flash('Username must be at least 3 characters long!', 'error')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long!', 'error')
            return render_template('register.html')
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'error')
            return render_template('register.html')
        
        if email and User.query.filter_by(email=email).first():
            flash('Email already exists!', 'error')
            return render_template('register.html')
        
        # Create new user with encryption keys
        hashed_password = generate_password_hash(password)
        new_user = User(
            username=username, 
            password_hash=hashed_password,
            first_name=first_name,
            last_name=last_name,
            email=email if email else None
        )
        
        # Generate E2E encryption keys
        public_key, private_key = new_user.generate_keys()
        
        db.session.add(new_user)
        db.session.flush()  # Get user ID
        
        # Create user profile
        profile = UserProfile(user_id=new_user.id)
        db.session.add(profile)
        
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip().lower()
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['public_key'] = user.public_key
            session.permanent = True  # respect PERMANENT_SESSION_LIFETIME
            
            # Update online status and session
            user.is_online = True
            user.last_seen = datetime.utcnow()
            user.last_login = datetime.utcnow()
            
            # Store user session for fast access
            with session_lock:
                user_sessions[user.id] = {
                    'last_activity': time.time(),
                    'public_key': user.public_key,
                    'is_online': True
                }
            
            db.session.commit()
            
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password!', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        # Update offline status
        user = User.query.get(session['user_id'])
        if user:
            user.is_online = False
            user.last_seen = datetime.utcnow()
            db.session.commit()
        
        # Remove from active sessions
        with session_lock:
            if session['user_id'] in user_sessions:
                del user_sessions[session['user_id']]
    
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Dashboard
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    friends = get_user_friends(session['user_id'])
    pending_requests = FriendRequest.query.filter_by(
        receiver_id=session['user_id'], 
        status='pending'
    ).all()
    
    return render_template('dashboard.html', user=user, friends=friends, pending_requests=pending_requests)

# Profile Management
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    profile = UserProfile.query.filter_by(user_id=session['user_id']).first()
    
    if not profile:
        profile = UserProfile(user_id=session['user_id'])
        db.session.add(profile)
        db.session.commit()
    
    return render_template('profile.html', user=user, profile=profile)

@app.route('/users/<int:user_id>')
def view_user_profile(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(user_id)
    if not user or not user.is_active:
        flash('User not found.', 'error')
        return redirect(url_for('dashboard'))
    profile = UserProfile.query.filter_by(user_id=user_id).first()
    friends = get_user_friends(user_id)
    return render_template('user_profile.html', user=user, profile=profile, friends=friends)

@app.route('/api/profile/update', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    user = User.query.get(session['user_id'])
    profile = UserProfile.query.filter_by(user_id=session['user_id']).first()
    
    if not profile:
        profile = UserProfile(user_id=session['user_id'])
        db.session.add(profile)
    
    # Update user fields
    if 'first_name' in data:
        user.first_name = data['first_name'].strip()
    if 'last_name' in data:
        user.last_name = data['last_name'].strip()
    if 'email' in data and data['email']:
        user.email = data['email'].strip()
    if 'bio' in data:
        profile.bio = data['bio'].strip()
    if 'display_name' in data:
        profile.display_name = data['display_name'].strip()
    if 'theme_preference' in data:
        profile.theme_preference = data['theme_preference']
    
    profile.last_updated = datetime.utcnow()
    db.session.commit()
    
    return jsonify({'message': 'Profile updated successfully'})

def _allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def _unique_filename(user_id, filename):
    name, ext = os.path.splitext(filename)
    token = secrets.token_hex(8)
    safe_name = f"u{user_id}_{int(time.time())}_{token}{ext.lower()}"
    return safe_name

@app.route('/api/profile/upload-picture', methods=['POST'])
def upload_profile_picture():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if 'picture' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['picture']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if not _allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type'}), 400
    filename = _unique_filename(session['user_id'], file.filename)
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(path)
    rel_path = f"/uploads/{filename}"
    user = User.query.get(session['user_id'])
    profile = UserProfile.query.filter_by(user_id=session['user_id']).first()
    # Delete old file if exists
    for existing in [user.profile_picture, getattr(profile, 'profile_picture', None)]:
        if existing and existing.startswith('/uploads/'):
            try:
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(existing)))
            except Exception:
                pass
    user.profile_picture = rel_path
    if profile:
        profile.profile_picture = rel_path
    db.session.commit()
    return jsonify({'message': 'Profile picture updated', 'url': rel_path})

@app.route('/api/profile/delete-picture', methods=['POST'])
def delete_profile_picture():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    user = User.query.get(session['user_id'])
    profile = UserProfile.query.filter_by(user_id=session['user_id']).first()
    pic = user.profile_picture or (profile.profile_picture if profile else None)
    if pic and pic.startswith('/uploads/'):
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(pic)))
        except Exception:
            pass
    user.profile_picture = None
    if profile:
        profile.profile_picture = None
    db.session.commit()
    return jsonify({'message': 'Profile picture deleted'})

@app.route('/uploads/<path:filename>')
def serve_upload(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/api/profile/change-username', methods=['POST'])
def change_username():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    new_username = data.get('new_username', '').strip().lower()
    
    if len(new_username) < 3:
        return jsonify({'error': 'Username must be at least 3 characters long'}), 400
    
    # Check if username already exists
    if User.query.filter_by(username=new_username).first():
        return jsonify({'error': 'Username already exists'}), 400
    
    user = User.query.get(session['user_id'])
    user.username = new_username
    session['username'] = new_username
    db.session.commit()
    
    return jsonify({'message': 'Username changed successfully', 'new_username': new_username})

# User Search with enhanced features
@app.route('/api/users/search')
def search_users():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    query = request.args.get('q', '').strip()
    if len(query) < 2:
        return jsonify([])
    
    # Enhanced search with multiple criteria
    users = User.query.filter(
        db.or_(
            User.username.contains(query),
            User.first_name.contains(query),
            User.last_name.contains(query)
        )
    ).filter(User.id != session['user_id']).filter(User.is_active == True).limit(20).all()
    
    return jsonify([{
        'id': user.id,
        'username': user.username,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'is_online': user.is_online,
        'last_seen': user.last_seen.strftime('%Y-%m-%d %H:%M:%S') if user.last_seen else None,
        'public_key': user.public_key
    } for user in users])

# Enhanced Friend System
@app.route('/api/friends/request', methods=['POST'])
def send_friend_request():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    receiver_id = data.get('receiver_id')
    message = data.get('message', '').strip()
    
    if not receiver_id:
        return jsonify({'error': 'Receiver ID required'}), 400
    
    # Check if already friends or request exists
    existing_friendship = Friendship.query.filter(
        db.or_(
            db.and_(Friendship.user_id == session['user_id'], Friendship.friend_id == receiver_id),
            db.and_(Friendship.user_id == receiver_id, Friendship.friend_id == session['user_id'])
        )
    ).first()
    
    if existing_friendship:
        return jsonify({'error': 'Already friends'}), 400
    
    existing_request = FriendRequest.query.filter_by(
        sender_id=session['user_id'], 
        receiver_id=receiver_id
    ).first()
    
    if existing_request:
        return jsonify({'error': 'Friend request already sent'}), 400
    
    # Create friend request with optional message
    friend_request = FriendRequest(
        sender_id=session['user_id'],
        receiver_id=receiver_id,
        message=message
    )
    db.session.add(friend_request)
    db.session.commit()
    
    return jsonify({'message': 'Friend request sent successfully'})

@app.route('/api/friends/request/<int:request_id>/<action>')
def handle_friend_request(request_id, action):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    friend_request = FriendRequest.query.get(request_id)
    if not friend_request or friend_request.receiver_id != session['user_id']:
        return jsonify({'error': 'Request not found'}), 404
    
    if action == 'accept':
        friend_request.status = 'accepted'
        
        # Create friendship with unique chat session
        friendship1 = Friendship(user_id=friend_request.sender_id, friend_id=friend_request.receiver_id)
        friendship2 = Friendship(user_id=friend_request.receiver_id, friend_id=friend_request.sender_id)
        
        # Create chat session
        chat_session = ChatSession(
            id=friendship1.chat_session_id,
            user1_id=min(friend_request.sender_id, friend_request.receiver_id),
            user2_id=max(friend_request.sender_id, friend_request.receiver_id)
        )
        
        db.session.add(friendship1)
        db.session.add(friendship2)
        db.session.add(chat_session)
        
        flash('Friend request accepted!', 'success')
        
    elif action == 'reject':
        friend_request.status = 'rejected'
        flash('Friend request rejected.', 'info')
    
    db.session.commit()
    return redirect(url_for('dashboard'))

# Ultra-Fast Messaging System with E2E Encryption
@app.route('/chat/<int:user_id>')
def direct_chat(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Check if they are friends
    friendship = Friendship.query.filter(
        db.or_(
            db.and_(Friendship.user_id == session['user_id'], Friendship.friend_id == user_id),
            db.and_(Friendship.user_id == user_id, Friendship.friend_id == session['user_id'])
        )
    ).first()
    
    if not friendship:
        flash('You can only chat with friends!', 'error')
        return redirect(url_for('dashboard'))
    
    other_user = User.query.get(user_id)
    # Compute freshness-based online indicator
    recent_seconds = (datetime.utcnow() - (other_user.last_seen or datetime.utcnow())).total_seconds() if other_user else 9999
    is_other_online = bool(other_user and other_user.is_online and recent_seconds < 120)
    return render_template('direct_chat.html', other_user=other_user, friendship=friendship, is_other_online=is_other_online)

@app.route('/api/chat/<int:user_id>/clear', methods=['POST'])
def clear_chat(user_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    friendship = Friendship.query.filter(
        db.or_(
            db.and_(Friendship.user_id == session['user_id'], Friendship.friend_id == user_id),
            db.and_(Friendship.user_id == user_id, Friendship.friend_id == session['user_id'])
        )
    ).first()
    if not friendship:
        return jsonify({'error': 'You can only clear chats with friends'}), 403
    # Delete messages for this chat session
    Message.query.filter_by(chat_session_id=friendship.chat_session_id).delete(synchronize_session=False)
    # Reset related metadata
    chat_session = ChatSession.query.get(friendship.chat_session_id)
    if chat_session:
        chat_session.last_message_at = datetime.utcnow()
        chat_session.last_message_id = None
        chat_session.unread_count_user1 = 0
        chat_session.unread_count_user2 = 0
    friendship.unread_count = 0
    # Clear cache and read receipts
    cache_key = f"{min(session['user_id'], user_id)}_{max(session['user_id'], user_id)}"
    with cache_lock:
        if cache_key in message_cache:
            message_cache[cache_key] = []
    with read_receipts_lock:
        _read_receipts.pop(friendship.chat_session_id, None)
    db.session.commit()
    return jsonify({'message': 'Chat cleared'})

@app.route('/api/account/delete', methods=['POST'])
def delete_account():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    user_id = session['user_id']
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    # Remove profile picture file
    if user.profile_picture and user.profile_picture.startswith('/uploads/'):
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(user.profile_picture)))
        except Exception:
            pass
    profile = UserProfile.query.filter_by(user_id=user_id).first()
    if profile and profile.profile_picture and profile.profile_picture.startswith('/uploads/'):
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(profile.profile_picture)))
        except Exception:
            pass
    # Delete related records
    MessageReaction.query.filter_by(user_id=user_id).delete(synchronize_session=False)
    # Delete messages involving user
    Message.query.filter(db.or_(Message.sender_id == user_id, Message.receiver_id == user_id)).delete(synchronize_session=False)
    # Delete chat sessions involving user
    ChatSession.query.filter(db.or_(ChatSession.user1_id == user_id, ChatSession.user2_id == user_id)).delete(synchronize_session=False)
    # Delete friendships and requests
    Friendship.query.filter(db.or_(Friendship.user_id == user_id, Friendship.friend_id == user_id)).delete(synchronize_session=False)
    FriendRequest.query.filter(db.or_(FriendRequest.sender_id == user_id, FriendRequest.receiver_id == user_id)).delete(synchronize_session=False)
    # Delete typing status
    TypingStatus.query.filter_by(user_id=user_id).delete(synchronize_session=False)
    # Delete profile
    UserProfile.query.filter_by(user_id=user_id).delete(synchronize_session=False)
    # Finally delete user
    db.session.delete(user)
    db.session.commit()
    session.clear()
    return jsonify({'message': 'Account deleted'})

@app.route('/api/messages/<int:user_id>')
def get_direct_messages(user_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Check if they are friends
    friendship = Friendship.query.filter(
        db.or_(
            db.and_(Friendship.user_id == session['user_id'], Friendship.friend_id == user_id),
            db.and_(Friendship.user_id == user_id, Friendship.friend_id == session['user_id'])
        )
    ).first()
    
    if not friendship:
        return jsonify({'error': 'You can only message friends'}), 403
    
    # Get messages from cache first, then database
    cache_key = f"{min(session['user_id'], user_id)}_{max(session['user_id'], user_id)}"
    
    with cache_lock:
        if cache_key in message_cache:
            cached_messages = message_cache[cache_key]
            if len(cached_messages) > 0:
                # Mark messages as read
                unread_ids = [msg['id'] for msg in cached_messages if msg['sender_id'] == user_id and not msg['is_read']]
                if unread_ids:
                    Message.query.filter(Message.id.in_(unread_ids)).update({'is_read': True}, synchronize_session=False)
                    db.session.commit()
                
                return jsonify(cached_messages)
    
    # Fallback to database
    messages = Message.query.filter_by(chat_session_id=friendship.chat_session_id).order_by(Message.timestamp.asc()).all()
    
    # Mark messages as read
    unread_messages = [msg for msg in messages if msg.sender_id == user_id and not msg.is_read]
    for msg in unread_messages:
        msg.is_read = True
    db.session.commit()
    # Track read receipts and update cache on initial load
    if unread_messages:
        # update cache
        cache_key = f"{min(session['user_id'], user_id)}_{max(session['user_id'], user_id)}"
        with cache_lock:
            cached_list = []
            for msg in messages:
                cached_list.append({
                    'id': msg.id,
                    'content': msg.content,
                    'sender_id': msg.sender_id,
                    'receiver_id': msg.receiver_id,
                    'is_read': msg.is_read,
                    'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    'message_type': msg.message_type
                })
            message_cache[cache_key] = cached_list
        # receipts
        with read_receipts_lock:
            rr = _read_receipts.setdefault(friendship.chat_session_id, [])
            now_ts = time.time()
            for m in unread_messages:
                rr.append({'id': m.id, 'ts': now_ts})
            if len(rr) > 500:
                _read_receipts[friendship.chat_session_id] = rr[-500:]
        try:
            print(f"DEBUG read:init-load chat={friendship.chat_session_id} count={len(unread_messages)} ids={[m.id for m in unread_messages]}")
        except Exception:
            pass
    
    # Format messages for response
    formatted_messages = []
    for msg in messages:
        formatted_messages.append({
            'id': msg.id,
            'content': msg.content,
            'sender_id': msg.sender_id,
            'receiver_id': msg.receiver_id,
            'is_read': msg.is_read,
            'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'message_type': msg.message_type
        })
    
    # Cache the messages
    with cache_lock:
        message_cache[cache_key] = formatted_messages
    
    return jsonify(formatted_messages)

@app.route('/api/messages/send', methods=['POST'])
def send_direct_message():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    receiver_id = data.get('receiver_id')
    content = data.get('content', '').strip()
    message_type = data.get('message_type', 'text')
    
    if not content or not receiver_id:
        return jsonify({'error': 'Content and receiver required'}), 400
    
    # Check if they are friends
    friendship = Friendship.query.filter(
        db.or_(
            db.and_(Friendship.user_id == session['user_id'], Friendship.friend_id == receiver_id),
            db.and_(Friendship.user_id == receiver_id, Friendship.friend_id == session['user_id'])
        )
    ).first()
    
    if not friendship:
        return jsonify({'error': 'You can only message friends'}), 403
    
    # Create message with plain text content
    new_message = Message(
        chat_session_id=friendship.chat_session_id,
        sender_id=session['user_id'],
        receiver_id=receiver_id,
        content=content,
        content_hash=hashlib.sha256(content.encode()).hexdigest(),
        message_type=message_type
    )
    
    db.session.add(new_message)
    db.session.flush()  # Get message ID
    
    # Update friendship last message info
    friendship.last_message_at = datetime.utcnow()
    friendship.unread_count += 1
    
    # Update chat session
    chat_session = ChatSession.query.get(friendship.chat_session_id)
    if chat_session:
        chat_session.last_message_at = datetime.utcnow()
        chat_session.last_message_id = new_message.id
        if receiver_id == chat_session.user1_id:
            chat_session.unread_count_user1 += 1
        else:
            chat_session.unread_count_user2 += 1
    
    # Add to cache immediately for ultra-fast delivery
    cache_key = f"{min(session['user_id'], receiver_id)}_{max(session['user_id'], receiver_id)}"
    
    with cache_lock:
        if cache_key not in message_cache:
            message_cache[cache_key] = []
        
        # Add message to cache
        cached_message = {
            'id': new_message.id,
            'content': content,
            'sender_id': new_message.sender_id,
            'receiver_id': new_message.receiver_id,
            'timestamp': new_message.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'message_type': message_type,
            'is_read': False
        }
        message_cache[cache_key].append(cached_message)
    
    db.session.commit()
    
    return jsonify({
        'id': new_message.id,
        'content': content,
        'sender_id': new_message.sender_id,
        'receiver_id': new_message.receiver_id,
        'timestamp': new_message.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        'message_type': message_type
    })

# Typing indicators
@app.route('/api/typing', methods=['POST'])
def set_typing():
    if 'user_id' not in session:
        return jsonify({'ok': False}), 200
    data = request.get_json() or {}
    other_user_id = data.get('other_user_id')
    is_typing = bool(data.get('is_typing', False))
    if not other_user_id:
        return jsonify({'error': 'other_user_id required'}), 400
    # Find friendship to get chat_session_id
    friendship = Friendship.query.filter(
        db.or_(
            db.and_(Friendship.user_id == session['user_id'], Friendship.friend_id == other_user_id),
            db.and_(Friendship.user_id == other_user_id, Friendship.friend_id == session['user_id'])
        )
    ).first()
    if not friendship:
        return jsonify({'error': 'Not friends'}), 403
    # Persist to DB to work across instances
    ts = TypingStatus(
        chat_session_id=friendship.chat_session_id,
        user_id=session.get('user_id'),
        last_typing_at=datetime.utcnow()
    )
    # upsert-like behavior
    existing = TypingStatus.query.filter_by(chat_session_id=ts.chat_session_id, user_id=ts.user_id).first()
    if existing:
        existing.last_typing_at = ts.last_typing_at
    else:
        db.session.add(ts)
    db.session.commit()
    try:
        print(f"DEBUG typing:set user={session['user_id']} other={other_user_id} chat={friendship.chat_session_id} is_typing={is_typing}")
    except Exception:
        pass
    return jsonify({'ok': True})

@app.route('/api/typing/ping', methods=['POST'])
def typing_ping():
    data = request.get_json() or {}
    chat_session_id = data.get('chat_session_id')
    typer_id = data.get('typer_id')
    if not chat_session_id or not typer_id:
        return jsonify({'ok': False}), 200
    # Persist to DB
    existing = TypingStatus.query.filter_by(chat_session_id=str(chat_session_id), user_id=int(typer_id)).first()
    if existing:
        existing.last_typing_at = datetime.utcnow()
    else:
        db.session.add(TypingStatus(chat_session_id=str(chat_session_id), user_id=int(typer_id), last_typing_at=datetime.utcnow()))
    db.session.commit()
    return jsonify({'ok': True})

@app.route('/api/typing/state')
def typing_state():
    chat_session_id = request.args.get('chat_session_id')
    other_id = request.args.get('other_id')
    if not chat_session_id or not other_id:
        return jsonify({'is_typing': False})
    rec = TypingStatus.query.filter_by(chat_session_id=str(chat_session_id), user_id=int(other_id)).first()
    is_typing = False
    if rec and rec.last_typing_at:
        is_typing = (datetime.utcnow() - rec.last_typing_at).total_seconds() < 4.0
    return jsonify({'is_typing': is_typing})

@app.route('/api/typing/<int:other_user_id>')
def get_typing(other_user_id):
    # Prefer explicit chat_session_id if provided (no auth needed)
    chat_session_id = request.args.get('chat_session_id')
    if not chat_session_id:
        # Fall back to resolving via session
        if 'user_id' not in session:
            return jsonify({'is_typing': False})
        friendship = Friendship.query.filter(
            db.or_(
                db.and_(Friendship.user_id == session['user_id'], Friendship.friend_id == other_user_id),
                db.and_(Friendship.user_id == other_user_id, Friendship.friend_id == session['user_id'])
            )
        ).first()
        if not friendship:
            return jsonify({'is_typing': False})
        chat_session_id = friendship.chat_session_id
    # Check if the OTHER user is typing
    # Read from DB (works across dynos/instances)
    rec = TypingStatus.query.filter_by(chat_session_id=str(chat_session_id), user_id=int(other_user_id)).first()
    is_typing = False
    if rec and rec.last_typing_at:
        delta = (datetime.utcnow() - rec.last_typing_at).total_seconds()
        is_typing = delta < 4.0
    try:
        print(f"DEBUG typing:get requester={session['user_id']} other={other_user_id} chat={friendship.chat_session_id} is_typing={is_typing}")
    except Exception:
        pass
    return jsonify({'is_typing': is_typing})

# Ultra-fast message retrieval with caching
@app.route('/api/messages/<int:user_id>/latest')
def get_latest_messages(user_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Check if they are friends
    friendship = Friendship.query.filter(
        db.or_(
            db.and_(Friendship.user_id == session['user_id'], Friendship.friend_id == user_id),
            db.and_(Friendship.user_id == user_id, Friendship.friend_id == session['user_id'])
        )
    ).first()
    
    if not friendship:
        return jsonify({'error': 'You can only message friends'}), 403
    
    last_timestamp = request.args.get('last_timestamp')
    cache_key = f"{min(session['user_id'], user_id)}_{max(session['user_id'], user_id)}"
    
    # Check cache first
    with cache_lock:
        if cache_key in message_cache:
            cached_messages = message_cache[cache_key]
            if last_timestamp:
                # Filter new messages since last timestamp
                new_messages = [
                    msg for msg in cached_messages 
                    if msg['timestamp'] > last_timestamp
                ]
            else:
                # Return last 50 messages from cache
                new_messages = cached_messages[-50:] if len(cached_messages) > 50 else cached_messages
            
            # Mark messages as read (for any new ones), and also catch same-second cases by scanning cache
            unread_ids = [msg['id'] for msg in new_messages if msg['sender_id'] == user_id and not msg['is_read']]
            if not unread_ids:
                # If no new messages triggered a read, still mark any unread from cache
                unread_ids = [cm['id'] for cm in cached_messages if cm['sender_id'] == user_id and not cm['is_read']]
            if unread_ids:
                Message.query.filter(Message.id.in_(unread_ids)).update({'is_read': True}, synchronize_session=False)
                db.session.commit()
                # Update cache entries to reflect read status
                for cm in cached_messages:
                    if cm['id'] in unread_ids:
                        cm['is_read'] = True
                # Track read receipts
                with read_receipts_lock:
                    rr = _read_receipts.setdefault(friendship.chat_session_id, [])
                    now_ts = time.time()
                    for mid in unread_ids:
                        rr.append({'id': mid, 'ts': now_ts})
                    if len(rr) > 500:
                        _read_receipts[friendship.chat_session_id] = rr[-500:]
                try:
                    print(f"DEBUG read:cache-marked chat={friendship.chat_session_id} count={len(unread_ids)} ids={unread_ids}")
                except Exception:
                    pass
            # Include side-channel read_ids for immediate UI updates
            return jsonify({'messages': new_messages, 'read_ids': unread_ids})
    
    # Fallback to database
    if last_timestamp:
        new_messages = Message.query.filter_by(chat_session_id=friendship.chat_session_id).filter(
            Message.timestamp > datetime.fromisoformat(last_timestamp.replace('Z', '+00:00'))
        ).order_by(Message.timestamp.asc()).all()
    else:
        new_messages = Message.query.filter_by(chat_session_id=friendship.chat_session_id).order_by(Message.timestamp.desc()).limit(50).all()
        new_messages.reverse()
    
    # Mark messages as read
    unread_messages = [msg for msg in new_messages if msg.sender_id == user_id and not msg.is_read]
    for msg in unread_messages:
        msg.is_read = True
    
    if unread_messages:
        db.session.commit()
        # Update cache too
        cache_key = f"{min(session['user_id'], user_id)}_{max(session['user_id'], user_id)}"
        with cache_lock:
            cached = message_cache.get(cache_key)
            if cached:
                unread_id_set = {m.id for m in unread_messages}
                for cm in cached:
                    if cm['id'] in unread_id_set:
                        cm['is_read'] = True
        # Track read receipts
        with read_receipts_lock:
            rr = _read_receipts.setdefault(friendship.chat_session_id, [])
            now_ts = time.time()
            for mid in [m.id for m in unread_messages]:
                rr.append({'id': mid, 'ts': now_ts})
            if len(rr) > 500:
                _read_receipts[friendship.chat_session_id] = rr[-500:]
        try:
            print(f"DEBUG read:db-marked chat={friendship.chat_session_id} count={len(unread_messages)} ids={[m.id for m in unread_messages]}")
        except Exception:
            pass
    
    # Format and return messages
    formatted_messages = []
    for msg in new_messages:
        formatted_messages.append({
            'id': msg.id,
            'content': msg.content,
            'sender_id': msg.sender_id,
            'receiver_id': msg.receiver_id,
            'is_read': msg.is_read,
            'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'message_type': msg.message_type
        })
    # Include side-channel read_ids for immediate UI updates
    read_ids = [m.id for m in unread_messages] if unread_messages else []
    return jsonify({'messages': formatted_messages, 'read_ids': read_ids})

@app.route('/api/messages/<int:user_id>/read-receipts')
def get_read_receipts(user_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    friendship = Friendship.query.filter(
        db.or_(
            db.and_(Friendship.user_id == session['user_id'], Friendship.friend_id == user_id),
            db.and_(Friendship.user_id == user_id, Friendship.friend_id == session['user_id'])
        )
    ).first()
    if not friendship:
        return jsonify({'read_ids': []})
    since_param = request.args.get('since')
    try:
        since = float(since_param) if since_param is not None else 0.0
    except Exception:
        since = 0.0
    with read_receipts_lock:
        entries = _read_receipts.get(friendship.chat_session_id, [])
        cutoff = time.time() - 60
        pruned = [e for e in entries if e['ts'] >= cutoff]
        if len(pruned) != len(entries):
            _read_receipts[friendship.chat_session_id] = pruned
        ready = [e for e in pruned if e['ts'] > since]
        read_ids = [e['id'] for e in ready]
        latest_ts = max([e['ts'] for e in ready], default=since)
    now = time.time()
    try:
        print(f"DEBUG read:poll requester={session['user_id']} other={user_id} chat={friendship.chat_session_id} since={since} returning={read_ids}")
    except Exception:
        pass
    return jsonify({'read_ids': read_ids, 'latest': latest_ts, 'now': now})

# Utility Functions
def get_user_friends(user_id):
    friendships = Friendship.query.filter_by(user_id=user_id).all()
    friends = []
    
    for friendship in friendships:
        friend = User.query.get(friendship.friend_id)
        if friend:
            # compute online freshness: online if last_seen within 120 seconds and active flag
            recent_seconds = (datetime.utcnow() - (friend.last_seen or datetime.utcnow())).total_seconds()
            computed_online = bool(friend.is_online and recent_seconds < 120)
            friends.append({
                'id': friend.id,
                'username': friend.username,
                'first_name': friend.first_name,
                'last_name': friend.last_name,
                'is_online': computed_online,
                'last_seen': friend.last_seen.strftime('%Y-%m-%d %H:%M:%S') if friend.last_seen else None,
                'public_key': friend.public_key,
                'chat_session_id': friendship.chat_session_id,
                'unread_count': friendship.unread_count,
                'last_message_at': friendship.last_message_at.strftime('%Y-%m-%d %H:%M:%S') if friendship.last_message_at else None,
                'profile_picture': friend.profile_picture
            })
    
    return friends

# Background cache cleanup
def cleanup_cache():
    """Clean up old cache entries and inactive sessions"""
    while True:
        time.sleep(300)  # Run every 5 minutes
        current_time = time.time()
        
        with cache_lock:
            # Remove old cache entries
            for key in list(message_cache.keys()):
                if len(message_cache[key]) > 1000:
                    message_cache[key] = message_cache[key][-500:]
        
        with session_lock:
            # Remove inactive sessions
            for user_id in list(user_sessions.keys()):
                if current_time - user_sessions[user_id]['last_activity'] > 3600:  # 1 hour
                    del user_sessions[user_id]

# Start cleanup thread
cleanup_thread = threading.Thread(target=cleanup_cache, daemon=True)
cleanup_thread.start()

# Database initialization function
def init_database():
    """Initialize database tables"""
    try:
        with app.app_context():
            db.create_all()
            print("Database initialized successfully with all tables!")
            print("Users, profiles, friendships, and messages tables ready!")
    except Exception as e:
        print(f"Database initialization failed: {e}")
        # Don't crash the app, just log the error

# Initialize database when app starts
init_database()


if __name__ == '__main__':
    app.run(debug=False, threaded=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
