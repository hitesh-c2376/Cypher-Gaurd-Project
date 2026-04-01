from flask import request, jsonify
from flask_jwt_extended import (
    create_access_token,
    verify_jwt_in_request,
    get_jwt,
    jwt_required
)
from datetime import datetime, timezone
from functools import wraps
from models import db, User, BlockedIP
from security import hash_password, verify_password
from logging_engine import log_event

ALLOWED_ROLES = {"viewer", "user"}
MAX_USERNAME_LEN = 50
MAX_PASSWORD_LEN = 128


def require_role(required_role):
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            if claims.get("role") != required_role:
                return jsonify({"message": "Access denied"}), 403
            return fn(*args, **kwargs)
        return decorator
    return wrapper


def register_routes(app):

    # =====================================================
    # REGISTER USER (public — viewer/user roles only)
    # =====================================================
    @app.route("/register", methods=["POST"])
    def register():
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"message": "Invalid JSON body"}), 400

        username = data.get("username", "")
        password = data.get("password", "")
        role = data.get("role", "viewer")

        if not username or not password:
            return jsonify({"message": "Username and password required"}), 400

        if len(username) > MAX_USERNAME_LEN:
            return jsonify({"message": f"Username too long (max {MAX_USERNAME_LEN} chars)"}), 400

        if len(password) > MAX_PASSWORD_LEN:
            return jsonify({"message": f"Password too long (max {MAX_PASSWORD_LEN} chars)"}), 400

        if role not in ALLOWED_ROLES:
            role = "viewer"

        if User.query.filter_by(username=username).first():
            log_event(
                event_type="REGISTER_FAIL",
                severity="MEDIUM",
                message=f"Registration failed: username {username} already exists",
                ip_address=request.remote_addr
            )
            return jsonify({"message": "User already exists"}), 400

        try:
            new_user = User(
                username=username,
                password_hash=hash_password(password),
                role=role,
                login_count=0
            )
            db.session.add(new_user)
            db.session.commit()
        except Exception:
            db.session.rollback()
            return jsonify({"message": "Registration failed due to a server error"}), 500

        log_event(
            event_type="REGISTER_SUCCESS",
            severity="INFO",
            message=f"New user registered: {username}",
            user_id=new_user.id,
            ip_address=request.remote_addr
        )

        return jsonify({"message": "User registered successfully"}), 201


    # =====================================================
    # LOGIN USER — tracks last_login and login_count
    # =====================================================
    @app.route("/login", methods=["POST"])
    def login():
        client_ip = request.remote_addr

        blocked = BlockedIP.query.filter_by(ip_address=client_ip).first()
        if blocked:
            return jsonify({"error": "Your IP has been blocked due to suspicious activity"}), 403

        data = request.get_json(silent=True)
        if not data:
            return jsonify({"message": "Invalid JSON body"}), 400

        username = data.get("username", "")
        password = data.get("password", "")

        if not username or not password:
            return jsonify({"message": "Username and password required"}), 400

        if len(username) > MAX_USERNAME_LEN or len(password) > MAX_PASSWORD_LEN:
            log_event(
                event_type="LOGIN_FAIL",
                severity="MEDIUM",
                message="Login rejected: oversized input",
                ip_address=client_ip
            )
            return jsonify({"message": "Invalid credentials"}), 401

        user = User.query.filter_by(username=username).first()

        if not user:
            log_event(
                event_type="LOGIN_FAIL",
                severity="HIGH",
                message="Login failed: unknown username attempted",
                ip_address=client_ip
            )
            return jsonify({"message": "Invalid credentials"}), 401

        if not user.is_active:
            log_event(
                event_type="LOGIN_BLOCKED_DISABLED_USER",
                severity="HIGH",
                message=f"Login attempt for disabled user: {username}",
                user_id=user.id,
                ip_address=client_ip
            )
            return jsonify({"message": "Account disabled due to security policy"}), 403

        if not verify_password(password, user.password_hash):
            log_event(
                event_type="LOGIN_FAIL",
                severity="HIGH",
                message=f"Login failed: wrong password for user {username}",
                user_id=user.id,
                ip_address=client_ip
            )
            return jsonify({"message": "Invalid credentials"}), 401

        # Track last login time and count
        try:
            user.last_login = datetime.now(timezone.utc)
            user.login_count = (user.login_count or 0) + 1
            db.session.commit()
        except Exception:
            db.session.rollback()

        token = create_access_token(
            identity=str(user.id),
            additional_claims={
                "username": user.username,
                "role": user.role
            }
        )

        log_event(
            event_type="LOGIN_SUCCESS",
            severity="INFO",
            message=f"Login successful for user: {username}",
            user_id=user.id,
            ip_address=client_ip
        )

        return jsonify({"access_token": token}), 200


    # =====================================================
    # ADMIN: CREATE ANY USER (ADMIN ONLY)
    # =====================================================
    @app.route("/admin/create-user", methods=["POST"])
    @jwt_required()
    @require_role("admin")
    def admin_create_user():
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"message": "Invalid JSON body"}), 400

        username = data.get("username", "")
        password = data.get("password", "")
        role = data.get("role", "viewer")

        if not username or not password:
            return jsonify({"message": "Username and password required"}), 400

        if len(username) > MAX_USERNAME_LEN:
            return jsonify({"message": f"Username too long (max {MAX_USERNAME_LEN})"}), 400

        if len(password) > MAX_PASSWORD_LEN:
            return jsonify({"message": f"Password too long (max {MAX_PASSWORD_LEN})"}), 400

        if role not in {"admin", "viewer", "user"}:
            role = "viewer"

        if User.query.filter_by(username=username).first():
            return jsonify({"message": "Username already exists"}), 400

        try:
            new_user = User(
                username=username,
                password_hash=hash_password(password),
                role=role,
                is_active=True,
                login_count=0
            )
            db.session.add(new_user)
            db.session.commit()
        except Exception:
            db.session.rollback()
            return jsonify({"message": "User creation failed"}), 500

        log_event(
            event_type="USER_CREATED_BY_ADMIN",
            severity="HIGH",
            message=f"Admin created new user: {username} with role: {role}",
            ip_address=request.remote_addr
        )

        return jsonify({"message": f"User {username} created successfully"}), 201