from flask import Flask, request, jsonify, redirect, session
from pymongo import MongoClient
from dotenv import load_dotenv
import os
import bcrypt
import jwt
from datetime import datetime, timedelta
import uuid
import requests
from requests_oauthlib import OAuth2Session
from flask_cors import CORS
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

load_dotenv()

app = Flask(__name__)
CORS(app, origins=["http://localhost:5173"], supports_credentials=True)
# Only used by Flask session for OAuth dance; not for JWT
app.secret_key = os.getenv('FLASK_SECRET', os.urandom(24))

# Configuration from .env
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017')
MONGO_DB = os.getenv('MONGO_DB', 'auth_demo')
JWT_SECRET = os.getenv('JWT_SECRET', 'please_change_me')
JWT_ALGORITHM = 'HS256'
JWT_EXP_HOURS = int(os.getenv('JWT_EXP_HOURS', '1'))

GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
GOOGLE_REDIRECT_URI = os.getenv('GOOGLE_REDIRECT_URI', 'http://localhost:5000/auth/google/callback')
GOOGLE_AUTH_BASE = 'https://accounts.google.com/o/oauth2/v2/auth'
GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token'
GOOGLE_USERINFO = 'https://www.googleapis.com/oauth2/v3/userinfo'
GOOGLE_SCOPE = ['openid', 'email', 'profile']

# MongoDB setup
client = MongoClient(MONGO_URI)
db = client[MONGO_DB]
users_col = db['users']
blacklist_col = db['token_blacklist'] 

# Helpers
def hash_password(plain_password: str) -> bytes:
    return bcrypt.hashpw(plain_password.encode('utf-8'), bcrypt.gensalt())

def check_password(plain_password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed)

def generate_jwt(user_id: str, email: str) -> str:
    jti = str(uuid.uuid4())
    payload = {
        'sub': str(user_id),
        'email': email,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(hours=JWT_EXP_HOURS),
        'jti': jti
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    # PyJWT in v2 returns str; in v1 it returned bytes. Ensure string.
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    return token

def decode_jwt(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise
    except Exception:
        raise

# JWT middleware decorator
from functools import wraps

def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', None)
        if not auth:
            return jsonify({'error': 'Authorization header missing'}), 401
        parts = auth.split()
        if parts[0].lower() != 'bearer' or len(parts) != 2:
            return jsonify({'error': 'Invalid Authorization header format. Expected: Bearer <token>'}), 401
        token = parts[1]
        try:
            payload = decode_jwt(token)
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except Exception:
            return jsonify({'error': 'Invalid token'}), 401
        # Check blacklist
        if blacklist_col.find_one({'jti': payload.get('jti')}):
            return jsonify({'error': 'Token has been revoked'}), 401
        # Attach payload to request context
        request.user = {
            'id': payload.get('sub'),
            'email': payload.get('email')
        }
        return f(*args, **kwargs)
    return decorated

# Routes
@app.route('/register', methods=['POST'])
def register():
    """Register user with email & password
    JSON body: {"email": "...", "password": "...", "name": "..."}
    """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON body'}), 400
    email = data.get('email')
    password = data.get('password')
    name = data.get('name')
    if not email or not password or not name:
        return jsonify({'error': 'Missing email/password/name'}), 400
    if users_col.find_one({'email': email}):
        return jsonify({'error': 'Email already registered'}), 409
    hashed = hash_password(password)
    user_doc = {
        'email': email,
        'password': hashed,
        'name': name,
        'profile_picture': None,
        'auth_provider': 'email_password',
    }
    try:
        res = users_col.insert_one(user_doc)
        user_id = res.inserted_id
        token = generate_jwt(user_id, email)
        return jsonify({'message': 'Registered', 'token': token}), 201
    except Exception as e:
        return jsonify({'error': 'Database error', 'details': str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON body'}), 400

    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({'error': 'Missing email/password'}), 400

    user = users_col.find_one({'email': email})
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401

    hashed = user.get('password')
    if hashed and isinstance(hashed, str):
        hashed = hashed.encode('utf-8')

    try:
        if not hashed or not check_password(password, hashed):
            return jsonify({'error': 'Invalid credentials'}), 401
    except Exception:
        return jsonify({'error': 'Password check failed'}), 500

    token = generate_jwt(user['_id'], email)
    return jsonify({'message': 'Logged in', 'token': token}), 200


# Google OAuth: browser flow redirect
@app.route('/auth/google')
def auth_google_redirect():
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        return jsonify({'error': 'Google OAuth not configured on server'}), 500
    oauth = OAuth2Session(GOOGLE_CLIENT_ID, redirect_uri=GOOGLE_REDIRECT_URI, scope=GOOGLE_SCOPE)
    authorization_url, state = oauth.authorization_url(GOOGLE_AUTH_BASE, access_type='offline', prompt='select_account')
    # store state in session for callback verification
    session['oauth_state'] = state
    return redirect(authorization_url)

# OAuth2 callback (browser-based)
# OAuth2 callback (browser-based)
@app.route('/auth/google/callback')
def auth_google_callback():
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        return jsonify({'error': 'Google OAuth not configured on server'}), 500

    state = session.get('oauth_state')
    oauth = OAuth2Session(GOOGLE_CLIENT_ID, state=state, redirect_uri=GOOGLE_REDIRECT_URI)

    try:
        token = oauth.fetch_token(
            GOOGLE_TOKEN_URL,
            client_secret=GOOGLE_CLIENT_SECRET,
            authorization_response=request.url
        )
    except Exception as e:
        return jsonify({'error': 'Token fetch failed', 'details': str(e)}), 400

    # Fetch userinfo from Google
    resp = oauth.get(GOOGLE_USERINFO)
    if resp.status_code != 200:
        return jsonify({'error': 'Failed to fetch user info', 'details': resp.text}), 400

    info = resp.json()
    email = info.get('email')
    name = info.get('name')
    picture = info.get('picture')

    if not email:
        return jsonify({'error': 'Google account did not provide email'}), 400

    # Find or create user
    user = users_col.find_one({'email': email})
    if not user:
        user_doc = {
            'email': email,
            'password': None,
            'name': name,
            'profile_picture': picture,
            'auth_provider': 'google'
        }
        res = users_col.insert_one(user_doc)
        user_id = res.inserted_id
    else:
        user_id = user['_id']
        users_col.update_one(
            {'_id': user_id},
            {'$set': {'profile_picture': picture, 'name': name}}
        )

    # Generate JWT for this user
    token_jwt = generate_jwt(user_id, email)

    # ✅ Redirect to frontend with token in hash fragment
    frontend_url = os.getenv('FRONTEND_URL', 'http://localhost:5173').rstrip('/')
    redirect_url = f"{frontend_url}/google-success#token={token_jwt}"
    return redirect(redirect_url)

# POST /login/google - Exchange auth code (suitable for mobile/web clients that send code)
@app.route('/login/google', methods=['POST'])
def login_google_with_code():
    """Accepts JSON: {"code": "auth_code_from_client", "redirect_uri": "...optional..."}
    Exchanges code for tokens and returns JWT.
    """
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        return jsonify({'error': 'Google OAuth not configured on server'}), 500
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON body'}), 400
    code = data.get('code')
    redirect_uri = data.get('redirect_uri', GOOGLE_REDIRECT_URI)
    if not code:
        return jsonify({'error': 'Missing code'}), 400
    oauth = OAuth2Session(GOOGLE_CLIENT_ID, redirect_uri=redirect_uri)
    try:
        token = oauth.fetch_token(GOOGLE_TOKEN_URL, client_secret=GOOGLE_CLIENT_SECRET, code=code)
    except Exception as e:
        return jsonify({'error': 'Token fetch failed', 'details': str(e)}), 400
    access_token = token.get('access_token')
    if not access_token:
        return jsonify({'error': 'No access token received from Google'}), 400
    # retrieve userinfo
    headers = {'Authorization': f'Bearer {access_token}'}
    resp = requests.get(GOOGLE_USERINFO, headers=headers)
    if resp.status_code != 200:
        return jsonify({'error': 'Failed to fetch user info', 'details': resp.text}), 400
    info = resp.json()
    email = info.get('email')
    name = info.get('name')
    picture = info.get('picture')
    if not email:
        return jsonify({'error': 'Google account did not provide email'}), 400
    # find or create
    user = users_col.find_one({'email': email})
    if not user:
        user_doc = {
            'email': email,
            'password': None,
            'name': name,
            'profile_picture': picture,
            'auth_provider': 'google'
        }
        res = users_col.insert_one(user_doc)
        user_id = res.inserted_id
    else:
        user_id = user['_id']
        users_col.update_one({'_id': user_id}, {'$set': {'profile_picture': picture, 'name': name}})
    token_jwt = generate_jwt(user_id, email)
    return jsonify({'message': 'Google login successful', 'token': token_jwt}), 200

@app.route('/protected', methods=['GET'])
@jwt_required
def protected_route():
    user = getattr(request, 'user', None)
    return jsonify({'message': f'Hello {user.get("email")}, you accessed a protected route!', 'user': user}), 200

@app.route('/logout', methods=['POST'])
@jwt_required
def logout():
    # blacklist the token by jti
    auth = request.headers.get('Authorization')
    token = auth.split()[1]
    try:
        payload = decode_jwt(token)
    except Exception:
        return jsonify({'error': 'Invalid token'}), 401
    jti = payload.get('jti')
    exp = payload.get('exp')
    blacklist_col.insert_one({'jti': jti, 'exp': datetime.utcfromtimestamp(exp)})
    return jsonify({'message': 'Logged out'}), 200

# Health check
@app.route('/')
def index():
    return jsonify({'message': 'Flask Auth Service running'}), 200

if __name__ == '__main__':
    app.run(debug=True)