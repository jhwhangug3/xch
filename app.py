from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import json
import hashlib
import secrets
import threading
import time
from cryptography.fernet import Fernet
import base64

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)

# Single database for all tables (simplified for now)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chatapp.db'
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
    return render_template('direct_chat.html', other_user=other_user, friendship=friendship)

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
            
            # Mark messages as read
            unread_ids = [msg['id'] for msg in new_messages if msg['sender_id'] == user_id and not msg['is_read']]
            if unread_ids:
                Message.query.filter(Message.id.in_(unread_ids)).update({'is_read': True}, synchronize_session=False)
                db.session.commit()
            
            return jsonify(new_messages)
    
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
    
    return jsonify(formatted_messages)

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
                'last_seen': friend.last_seen.strftime('%Y-%m-%d %H:%M:%S') if friend.last_seen else None,
                'public_key': friend.public_key,
                'chat_session_id': friendship.chat_session_id,
                'unread_count': friendship.unread_count,
                'last_message_at': friendship.last_message_at.strftime('%Y-%m-%d %H:%M:%S') if friendship.last_message_at else None
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

if __name__ == '__main__':
    # Force delete any existing databases to ensure fresh schema
    import os
    for db_file in ['users.db', 'chats.db', 'database.db', 'chatapp.db']:
        if os.path.exists(db_file):
            os.remove(db_file)
            print(f"Deleted old database: {db_file}")
    
    print("Creating fresh database with new schema...")
    
    with app.app_context():
        # Create all tables in main database
        db.create_all()
        print("✅ Database created successfully with all tables!")
        print("🎉 Users, profiles, friendships, and messages tables ready!")
    
    app.run(debug=True, threaded=True, host='0.0.0.0', port=5000)