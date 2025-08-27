from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from io import BytesIO
import base64
import types
import os
import hashlib
import secrets
import threading
import time
from cryptography.fernet import Fernet
try:
    from pywebpush import webpush, WebPushException
    PUSH_AVAILABLE = True
except ImportError:
    PUSH_AVAILABLE = False
    webpush = None
    WebPushException = Exception
import json
import base64
from markupsafe import Markup, escape
import re
from werkzeug.utils import secure_filename
import requests

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
    images_dir = os.path.join(app.static_folder, 'images')
    return send_from_directory(images_dir, 'fav.png', mimetype='image/png')

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

# Auto-migration function to add missing columns
def run_auto_migration():
    """Automatically add missing columns to the database"""
    try:
        with app.app_context():
            # Check if location column exists
            result = db.session.execute(db.text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'user_profiles' 
                AND column_name = 'location'
            """))
            
            if not result.fetchone():
                print("🔄 Auto-migrating: Adding location column to user_profiles table...")
                db.session.execute(db.text("""
                    ALTER TABLE user_profiles 
                    ADD COLUMN location VARCHAR(200) DEFAULT NULL
                """))
                db.session.commit()
                print("✅ Successfully added location column to user_profiles table")
            else:
                print("✅ Location column already exists in user_profiles table")
                
    except Exception as e:
        print(f"⚠️ Auto-migration warning: {e}")
        print("This is normal if the column already exists or if there are permission issues")
        
    # Force SQLAlchemy to refresh table metadata after migration
    try:
        with app.app_context():
            db.engine.execute(db.text("SELECT 1"))  # Test connection
            print("🔄 Refreshing SQLAlchemy table metadata...")
            # Clear any cached table definitions
            db.Model.metadata.clear()
            db.Model.metadata.reflect(bind=db.engine)
            print("✅ Table metadata refreshed successfully")
    except Exception as e:
        print(f"⚠️ Metadata refresh warning: {e}")

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
    # Make location optional - it will be added by migration
    location = db.Column(db.String(200), nullable=True, default=None)
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'display_name': self.display_name,
            'bio': self.bio,
            'profile_picture': self.profile_picture,
            'theme_preference': self.theme_preference,
            'timezone': self.timezone,
            'language': self.language,
            'location': getattr(self, 'location', None)  # Safely get location
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

class Avatar(db.Model):
    __tablename__ = 'avatars'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), primary_key=True)
    mime_type = db.Column(db.String(50), nullable=False)
    data_b64 = db.Column(db.Text, nullable=False)

class PushSubscription(db.Model):
    __tablename__ = 'push_subscriptions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), index=True, nullable=False)
    endpoint = db.Column(db.Text, unique=True, nullable=False)
    p256dh = db.Column(db.String(255), nullable=False)
    auth = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

# Routes
@app.context_processor
def inject_user_context():
    try:
        if 'user_id' in session:
            u = User.query.get(session['user_id'])
            return { 'user': u }
    except Exception:
        pass
    # Provide a safe dummy so templates that access user.* don't 500
    return { 'user': types.SimpleNamespace(username='', first_name='', last_name='', profile_picture=None, is_online=False) }

def get_profile_url(user):
    """Helper function to generate consistent profile URLs"""
    if hasattr(user, 'username') and user.username:
        return url_for('view_user_profile_by_username', username=user.username)
    elif hasattr(user, 'id') and user.id:
        return url_for('view_user_profile', user_id=user.id)
    return '#'

@app.context_processor
def inject_helpers():
    """Inject helper functions into templates"""
    return {
        'get_profile_url': get_profile_url
    }

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
    
    try:
        profile = UserProfile.query.filter_by(user_id=session['user_id']).first()
        
        if not profile:
            profile = UserProfile(user_id=session['user_id'])
            db.session.add(profile)
            db.session.commit()
        
        # Get links from privacy_settings
        links = []
        try:
            if profile and profile.privacy_settings:
                ps = json.loads(profile.privacy_settings)
                links = ps.get('links') or []
        except Exception:
            links = []
            
    except Exception as e:
        # Handle case where location column doesn't exist yet
        print(f"Warning: Database schema issue: {e}")
        # Create a minimal profile object with default values
        profile = type('Profile', (), {
            'bio': '',
            'location': '',
            'timezone': 'UTC',
            'privacy_settings': '{}'
        })()
        links = []
    
    return render_template('profile.html', user=user, profile=profile, links=links)

@app.route('/@<username>')
def view_user_profile_by_username(username):
    """New username-based profile route - site/@username"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.filter_by(username=username).first()
    if not user or not user.is_active:
        flash('User not found.', 'error')
        return redirect(url_for('dashboard'))
    
    profile = UserProfile.query.filter_by(user_id=user.id).first()
    friends = get_user_friends(user.id)
    me = User.query.get(session['user_id'])
    links = []
    try:
        if profile and profile.privacy_settings:
            ps = json.loads(profile.privacy_settings)
            links = ps.get('links') or []
    except Exception:
        links = []
    return render_template('user_profile.html', me=me, user=user, profile=profile, friends=friends, links=links)

@app.route('/user/<username>')
def view_user_profile_by_username_alt(username):
    """Alternative username-based profile route - site/user/username"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.filter_by(username=username).first()
    if not user or not user.is_active:
        flash('User not found.', 'error')
        return redirect(url_for('dashboard'))
    
    profile = UserProfile.query.filter_by(user_id=user.id).first()
    friends = get_user_friends(user.id)
    me = User.query.get(session['user_id'])
    links = []
    try:
        if profile and profile.privacy_settings:
            ps = json.loads(profile.privacy_settings)
            links = ps.get('links') or []
    except Exception:
        links = []
    return render_template('user_profile.html', me=me, user=user, profile=profile, friends=friends, links=links)

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
    me = User.query.get(session['user_id'])
    links = []
    try:
        if profile and profile.privacy_settings:
            ps = json.loads(profile.privacy_settings)
            links = ps.get('links') or []
    except Exception:
        links = []
    return render_template('user_profile.html', me=me, user=user, profile=profile, friends=friends, links=links)

@app.route('/api/profile/update', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    user = User.query.get(session['user_id'])
    
    try:
        profile = UserProfile.query.filter_by(user_id=session['user_id']).first()
        
        if not profile:
            profile = UserProfile(user_id=session['user_id'])
            db.session.add(profile)
        
        # Handle username change first
        if 'new_username' in data and data['new_username']:
            new_username = data['new_username'].strip()
            if new_username != user.username:
                # Check if username is already taken
                existing_user = User.query.filter_by(username=new_username).first()
                if existing_user and existing_user.id != user.id:
                    return jsonify({'error': 'Username already taken'}), 400
                user.username = new_username
        
        # Update user fields
        if 'first_name' in data:
            user.first_name = data['first_name'].strip()
        if 'last_name' in data:
            user.last_name = data['last_name'].strip()
        if 'email' in data and data['email']:
            user.email = data['email'].strip()
        
        # Update profile fields
        if 'bio' in data:
            profile.bio = data['bio'].strip()
        if 'display_name' in data:
            profile.display_name = data['display_name'].strip()
        if 'theme_preference' in data:
            profile.theme_preference = data['theme_preference']
        
        # Handle location and timezone fields that might not exist in the database yet
        try:
            if 'location' in data:
                profile.location = data['location'].strip()
            if 'timezone' in data:
                profile.timezone = data['timezone'].strip()
        except AttributeError:
            # If the location/timezone columns don't exist yet, skip them
            print("Warning: location/timezone columns not available in database yet")
            pass
        
        # Update notification settings
        if 'notification_settings' in data:
            try:
                existing_settings = json.loads(profile.notification_settings) if profile.notification_settings else {}
            except Exception:
                existing_settings = {}
            existing_settings.update(data['notification_settings'])
            profile.notification_settings = json.dumps(existing_settings)
        
        # Update privacy settings
        if 'privacy_settings' in data:
            try:
                existing_settings = json.loads(profile.privacy_settings) if profile.privacy_settings else {}
            except Exception:
                existing_settings = {}
            existing_settings.update(data['privacy_settings'])
            profile.privacy_settings = json.dumps(existing_settings)

        # Store links array separately inside privacy_settings
        if 'links' in data and isinstance(data['links'], list):
            try:
                settings = json.loads(profile.privacy_settings) if profile.privacy_settings else {}
            except Exception:
                settings = {}
            # Normalize links: keep only allowed keys
            normalized = []
            for link in data['links']:
                if not isinstance(link, dict):
                    continue
                title = (link.get('title') or '').strip()
                url = (link.get('url') or '').strip()
                if not url:
                    continue
                normalized.append({'title': title[:60], 'url': url[:512]})
            settings['links'] = normalized
            profile.privacy_settings = json.dumps(settings)
        
        profile.last_updated = datetime.utcnow()
        db.session.commit()
        
        return jsonify({'message': 'Profile updated successfully'})
        
    except Exception as e:
        print(f"Error updating profile: {e}")
        return jsonify({'error': 'Failed to update profile'}), 500

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
    # Read file bytes and store in DB (base64) for persistence across restarts
    blob = file.read()
    mime = file.mimetype or 'image/png'
    encoded = base64.b64encode(blob).decode('ascii')
    # Upsert avatar
    existing = Avatar.query.filter_by(user_id=session['user_id']).first()
    if existing:
        existing.mime_type = mime
        existing.data_b64 = encoded
    else:
        db.session.add(Avatar(user_id=session['user_id'], mime_type=mime, data_b64=encoded))
    # Point profile_picture to served endpoint
    rel_path = url_for('get_avatar', user_id=session['user_id'])
    user = User.query.get(session['user_id'])
    profile = UserProfile.query.filter_by(user_id=session['user_id']).first()
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
    # Remove from DB avatar storage
    Avatar.query.filter_by(user_id=session['user_id']).delete(synchronize_session=False)
    user.profile_picture = None
    if profile:
        profile.profile_picture = None
    db.session.commit()
    return jsonify({'message': 'Profile picture deleted'})

@app.route('/uploads/<path:filename>')
def serve_upload(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/api/avatar/<int:user_id>')
def get_avatar(user_id):
    avatar = Avatar.query.filter_by(user_id=user_id).first()
    if not avatar:
        return jsonify({'error': 'not found'}), 404
    try:
        raw = base64.b64decode(avatar.data_b64)
    except Exception:
        return jsonify({'error': 'corrupt'}), 500
    return app.response_class(raw, mimetype=avatar.mime_type)

# Web Push configuration
VAPID_PUBLIC_KEY = os.environ.get('VAPID_PUBLIC_KEY')
VAPID_PRIVATE_KEY = os.environ.get('VAPID_PRIVATE_KEY')
VAPID_CLAIMS = {
    'sub': os.environ.get('VAPID_SUBJECT', 'mailto:admin@example.com')
}

@app.route('/api/notifications/vapid-public-key')
def vapid_public_key():
    if not PUSH_AVAILABLE:
        return jsonify({'error': 'Push notifications not available'}), 503
    if not VAPID_PUBLIC_KEY:
        return jsonify({'error': 'VAPID not configured'}), 503
    return jsonify({'key': VAPID_PUBLIC_KEY})

@app.route('/api/notifications/subscribe', methods=['POST'])
def subscribe_notifications():
    if not PUSH_AVAILABLE:
        return jsonify({'error': 'Push notifications not available'}), 503
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    data = request.get_json() or {}
    subscription = data.get('subscription')
    if not subscription:
        return jsonify({'error': 'Missing subscription'}), 400
    endpoint = subscription.get('endpoint')
    keys = subscription.get('keys', {})
    p256dh = keys.get('p256dh')
    auth_key = keys.get('auth')
    if not endpoint or not p256dh or not auth_key:
        return jsonify({'error': 'Invalid subscription'}), 400
    existing = PushSubscription.query.filter_by(endpoint=endpoint).first()
    if existing:
        existing.user_id = session['user_id']
        existing.p256dh = p256dh
        existing.auth = auth_key
    else:
        db.session.add(PushSubscription(
            user_id=session['user_id'], endpoint=endpoint, p256dh=p256dh, auth=auth_key
        ))
    db.session.commit()
    return jsonify({'ok': True})

@app.route('/api/notifications/unsubscribe', methods=['POST'])
def unsubscribe_notifications():
    if not PUSH_AVAILABLE:
        return jsonify({'error': 'Push notifications not available'}), 503
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    data = request.get_json() or {}
    endpoint = (data.get('subscription') or {}).get('endpoint') or data.get('endpoint')
    if not endpoint:
        return jsonify({'error': 'Missing endpoint'}), 400
    PushSubscription.query.filter_by(endpoint=endpoint).delete(synchronize_session=False)
    db.session.commit()
    return jsonify({'ok': True})

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
    
    me = User.query.get(session['user_id'])
    other_user = User.query.get(user_id)
    # Simple online indicator based on is_online flag
    is_other_online = bool(other_user and other_user.is_online)
    return render_template('direct_chat.html', me=me, other_user=other_user, friendship=friendship, is_other_online=is_other_online)

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

    # Send Web Push notification to receiver (if configured)
    if PUSH_AVAILABLE and VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY:
        try:
            subs = PushSubscription.query.filter_by(user_id=receiver_id).all()
            if subs:
                payload = json.dumps({
                    'title': 'New message',
                    'body': content[:140],
                    'sender_id': new_message.sender_id,
                    'chat_session_id': friendship.chat_session_id,
                    'url': url_for('direct_chat', user_id=session['user_id'], _external=True)
                })
                for s in subs:
                    try:
                        webpush(
                            subscription_info={
                                'endpoint': s.endpoint,
                                'keys': {'p256dh': s.p256dh, 'auth': s.auth}
                            },
                            data=payload,
                            vapid_private_key=VAPID_PRIVATE_KEY,
                            vapid_claims=VAPID_CLAIMS
                        )
                    except WebPushException as e:
                        try:
                            print(f"WebPush failed: {e}")
                        except Exception:
                            pass
        except Exception:
            pass

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
            friends.append({
                'id': friend.id,
                'username': friend.username,
                'first_name': friend.first_name,
                'last_name': friend.last_name,
                'is_online': friend.is_online,
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

# Presence and Location APIs
@app.route('/api/presence/ping', methods=['POST'])
def presence_ping():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    user.is_online = True
    user.last_login = datetime.utcnow()
    try:
        with session_lock:
            user_sessions[user.id] = {
                'last_activity': time.time(),
                'public_key': user.public_key,
                'is_online': True
            }
    except Exception:
        pass
    db.session.commit()
    return jsonify({'ok': True, 'ts': int(time.time())})

# Mark user as active on every request for precise presence
@app.before_request
def _mark_active_request():
    try:
        uid = session.get('user_id')
        if uid:
            with session_lock:
                sess = user_sessions.get(uid) or {}
                sess['last_activity'] = time.time()
                sess['is_online'] = True
                sess['public_key'] = sess.get('public_key')
                user_sessions[uid] = sess
            # Opportunistically set DB flag without heavy writes more often than every 60s
            u = User.query.get(uid)
            if u:
                now = datetime.utcnow()
                if not u.last_login or (now - (u.last_login or now)).total_seconds() > 60:
                    u.last_login = now
                    u.is_online = True
                    db.session.commit()
    except Exception:
        pass

# Presence window configuration (seconds)
_PRESENCE_WINDOW_S = 30

@app.route('/api/presence/<int:user_id>')
def presence_get(user_id):
    u = User.query.get(user_id)
    if not u or not u.is_active:
        return jsonify({'online': False, 'last_seen': None})
    active_recent = False
    try:
        with session_lock:
            s = user_sessions.get(user_id)
            if s and (time.time() - s.get('last_activity', 0)) < _PRESENCE_WINDOW_S:
                active_recent = True
    except Exception:
        pass
    online = bool(active_recent)
    last_seen = (u.last_login.isoformat() if u.last_login else None)
    return jsonify({'online': online, 'last_seen': last_seen})

@app.route('/api/presence/bulk')
def presence_bulk():
    ids_param = request.args.get('ids', '')
    try:
        ids = [int(x) for x in ids_param.split(',') if x.strip()]
    except Exception:
        ids = []
    result = {}
    now = time.time()
    with session_lock:
        for uid in ids:
            s = user_sessions.get(uid) or {}
            online = (now - s.get('last_activity', 0)) < _PRESENCE_WINDOW_S
            result[str(uid)] = {'online': online}
    return jsonify(result)

@app.route('/api/profile/update-location', methods=['POST'])
def update_location():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    data = request.get_json() or {}
    lat = data.get('lat')
    lon = data.get('lon')
    tz = (data.get('timezone') or '').strip() or None
    if lat is None or lon is None:
        return jsonify({'error': 'lat and lon required'}), 400
    profile = UserProfile.query.filter_by(user_id=session['user_id']).first()
    if not profile:
        profile = UserProfile(user_id=session['user_id'])
        db.session.add(profile)
        db.session.flush()
    # Store in privacy_settings JSON
    try:
        existing = json.loads(profile.privacy_settings) if profile.privacy_settings else {}
    except Exception:
        existing = {}
    existing['location'] = {'lat': float(lat), 'lon': float(lon)}
    if tz:
        profile.timezone = tz
        existing['timezone'] = tz
    profile.privacy_settings = json.dumps(existing)
    profile.last_updated = datetime.utcnow()
    db.session.commit()
    return jsonify({'ok': True})

@app.route('/api/profile/location/<int:user_id>')
def get_location(user_id):
    user = User.query.get(user_id)
    if not user or not user.is_active:
        return jsonify({'error': 'User not found'}), 404
    profile = UserProfile.query.filter_by(user_id=user_id).first()
    data = {'lat': None, 'lon': None, 'timezone': None}
    if profile:
        try:
            settings = json.loads(profile.privacy_settings) if profile.privacy_settings else {}
        except Exception:
            settings = {}
        loc = settings.get('location') or {}
        data['lat'] = loc.get('lat')
        data['lon'] = loc.get('lon')
        data['timezone'] = settings.get('timezone') or profile.timezone
    return jsonify(data)

# Chat attachments upload
@app.route('/api/chat/upload', methods=['POST'])
def upload_chat_attachment():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    f = request.files['file']
    if f.filename == '':
        return jsonify({'error': 'Empty filename'}), 400
    # Allow common types
    allowed = {'image/jpeg','image/png','image/gif','image/webp','application/pdf','text/plain','application/zip','application/x-rar-compressed','application/vnd.openxmlformats-officedocument.wordprocessingml.document','application/msword'}
    if f.mimetype not in allowed:
        # Still accept but mark generic
        pass
    # Save to uploads/chat/
    chat_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'chat')
    os.makedirs(chat_dir, exist_ok=True)
    filename = secure_filename(f.filename)
    # Avoid collisions
    ts = datetime.utcnow().strftime('%Y%m%d%H%M%S%f')
    base, ext = os.path.splitext(filename)
    safe_name = f"{base}_{ts}{ext}"
    path = os.path.join(chat_dir, safe_name)
    f.save(path)
    url = url_for('serve_upload', filename=f"chat/{safe_name}")
    return jsonify({'url': url})

# Geocoding proxy (avoids CORS and requires UA)
@app.route('/api/geo/search')
def geo_search():
    q = (request.args.get('q') or '').strip()
    if len(q) < 2:
        return jsonify([])
    out = []
    headers = {'User-Agent': 'xch-app/1.0 (+https://example.com)'}
    try:
        r1 = requests.get('https://nominatim.openstreetmap.org/search', params={
            'format': 'jsonv2', 'addressdetails': 1, 'limit': 5, 'q': q
        }, headers=headers, timeout=6)
        if r1.ok:
            out = r1.json()
    except Exception:
        out = []
    if not out:
        try:
            r2 = requests.get('https://geocode.maps.co/search', params={'q': q}, headers=headers, timeout=6)
            if r2.ok:
                j2 = r2.json()
                if isinstance(j2, list):
                    out = [{ 'display_name': it.get('display_name'), 'lat': it.get('lat'), 'lon': it.get('lon') } for it in j2]
        except Exception:
            pass
    # Normalize output
    norm = []
    for it in out[:5]:
        name = (it.get('display_name') or '').strip()
        lat = it.get('lat'); lon = it.get('lon')
        if not name or not lat or not lon:
            continue
        norm.append({'display_name': name, 'lat': str(lat), 'lon': str(lon)})
    return jsonify(norm)

# Jinja filter to linkify @username mentions and URLs in bio safely
@app.template_filter('linkify_bio')
def linkify_bio(text):
    if not text:
        return ''
    try:
        s = escape(text)
        # Linkify @username (letters, numbers, underscores, dots, hyphens)
        s = re.sub(r'@([A-Za-z0-9_\.\-]+)', r'<a href="/@\1">@\1</a>', s)
        # Linkify URLs (http/https)
        s = re.sub(r'(https?://[\w\-._~:/?#\[\]@!$&\'()*+,;=%]+)', r'<a href="\1" target="_blank" rel="noopener">\1</a>', s)
        return Markup(s)
    except Exception:
        return escape(text)


if __name__ == '__main__':
    host = os.environ.get('HOST', '127.0.0.1')
    port = int(os.environ.get('PORT', 5050))
    
    # Create tables if they don't exist and run auto-migration
    with app.app_context():
        db.create_all()
        print("Database initialized successfully with all tables!")
        print("Users, profiles, friendships, and messages tables ready!")
        
        # Run auto-migration to add missing columns
        run_auto_migration()
    
    app.run(debug=False, threaded=True, host=host, port=port)
