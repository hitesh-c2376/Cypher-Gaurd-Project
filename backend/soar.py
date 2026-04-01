from flask import jsonify, request
from flask_jwt_extended import jwt_required
from datetime import datetime, timezone, timedelta
from auth import require_role
from soar_engine import execute_soar_actions
from models import db, Device, User, BlockedIP
from logging_engine import log_event
from security import hash_password

MAX_DEVICE_ID_LEN = 100
IST = timezone(timedelta(hours=5, minutes=30))


def _format_ist(dt):
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(IST).strftime("%Y-%m-%d %H:%M:%S")


def register_soar_routes(app):

    # =====================================================
    # RUN SOAR MANUALLY
    # =====================================================
    @app.route("/run-soar", methods=["POST"])
    @jwt_required()
    @require_role("admin")
    def run_soar():
        execute_soar_actions()
        return jsonify({"message": "SOAR automation executed successfully"}), 200


    # =====================================================
    # UNLOCK DEVICE (ADMIN ONLY)
    # =====================================================
    @app.route("/device/<device_id>/unlock", methods=["POST"])
    @jwt_required()
    @require_role("admin")
    def unlock_device(device_id):
        device_id = device_id[:MAX_DEVICE_ID_LEN]
        device = Device.query.filter_by(device_id=device_id).first()

        if not device:
            return jsonify({"message": "Device not found"}), 404

        device.status = "ACTIVE"
        device.key_rotation_required = False

        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            return jsonify({"message": "Failed to unlock device"}), 500

        log_event(
            event_type="DEVICE_UNLOCKED",
            severity="HIGH",
            message="Device manually unlocked by admin",
            device_id=device_id,
            ip_address=request.remote_addr
        )

        return jsonify({"message": f"Device {device_id} unlocked successfully"}), 200


    # =====================================================
    # LIST USERS — returns { users, total, stats }
    # =====================================================
    @app.route("/users", methods=["GET"])
    @jwt_required()
    @require_role("admin")
    def list_users():
        users = User.query.order_by(User.created_at.asc()).all()

        user_list = []
        for u in users:
            user_list.append({
                "id": u.id,
                "username": u.username,
                "role": u.role,
                "is_active": u.is_active,
                "login_count": u.login_count or 0,
                "last_login": _format_ist(u.last_login),
                "created_at": _format_ist(u.created_at),
            })

        total = len(user_list)
        admins = sum(1 for u in users if u.role == "admin")
        active = sum(1 for u in users if u.is_active)
        disabled = total - active

        return jsonify({
            "users": user_list,
            "total": total,
            "stats": {
                "total": total,
                "admins": admins,
                "active": active,
                "disabled": disabled
            }
        }), 200


    # =====================================================
    # DISABLE USER (ADMIN ONLY)
    # =====================================================
    @app.route("/users/<int:user_id>/disable", methods=["POST"])
    @jwt_required()
    @require_role("admin")
    def disable_user(user_id):
        user = User.query.get(user_id)
        if not user:
            return jsonify({"message": "User not found"}), 404

        user.is_active = False
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            return jsonify({"message": "Failed to disable user"}), 500

        log_event(
            event_type="USER_DISABLED",
            severity="HIGH",
            message=f"User {user.username} disabled by admin",
            user_id=user_id,
            ip_address=request.remote_addr
        )

        return jsonify({"message": f"User {user.username} disabled"}), 200


    # =====================================================
    # RESET PASSWORD (ADMIN ONLY)
    # =====================================================
    @app.route("/users/<int:user_id>/reset-password", methods=["POST"])
    @jwt_required()
    @require_role("admin")
    def reset_user_password(user_id):
        data = request.get_json(silent=True)
        if not data or not data.get("new_password"):
            return jsonify({"message": "new_password required"}), 400

        new_password = data.get("new_password", "")

        if len(new_password) < 6:
            return jsonify({"message": "Password must be at least 6 characters"}), 400

        if len(new_password) > 128:
            return jsonify({"message": "Password too long"}), 400

        user = User.query.get(user_id)
        if not user:
            return jsonify({"message": "User not found"}), 404

        try:
            user.password_hash = hash_password(new_password)
            db.session.commit()
        except Exception:
            db.session.rollback()
            return jsonify({"message": "Password reset failed"}), 500

        log_event(
            event_type="PASSWORD_RESET_BY_ADMIN",
            severity="HIGH",
            message=f"Password reset for user {user.username} by admin",
            user_id=user_id,
            ip_address=request.remote_addr
        )

        return jsonify({"message": f"Password for {user.username} reset successfully"}), 200


    # =====================================================
    # LIST BLOCKED IPs (ADMIN ONLY)
    # =====================================================
    @app.route("/blocked-ips", methods=["GET"])
    @jwt_required()
    @require_role("admin")
    def list_blocked_ips():
        ips = BlockedIP.query.order_by(BlockedIP.created_at.desc()).all()
        return jsonify([
            {
                "id": ip.id,
                "ip_address": ip.ip_address,
                "reason": ip.reason,
                "created_at": ip.created_at.isoformat() if ip.created_at else None
            }
            for ip in ips
        ]), 200


    # =====================================================
    # UNBLOCK IP (ADMIN ONLY)
    # =====================================================
    @app.route("/blocked-ips/<int:ip_id>/unblock", methods=["DELETE"])
    @jwt_required()
    @require_role("admin")
    def unblock_ip(ip_id):
        blocked = BlockedIP.query.get(ip_id)
        if not blocked:
            return jsonify({"message": "Blocked IP not found"}), 404

        ip_address = blocked.ip_address
        try:
            db.session.delete(blocked)
            db.session.commit()
        except Exception:
            db.session.rollback()
            return jsonify({"message": "Failed to unblock IP"}), 500

        log_event(
            event_type="IP_UNBLOCKED",
            severity="HIGH",
            message=f"IP {ip_address} manually unblocked by admin",
            ip_address=request.remote_addr
        )

        return jsonify({"message": f"IP {ip_address} unblocked"}), 200
    
    # =====================================================
    # DELETE USER (ADMIN ONLY)
    # =====================================================
    @app.route("/users/<int:user_id>/delete", methods=["DELETE"])
    @jwt_required()
    @require_role("admin")
    def delete_user(user_id):
        from flask_jwt_extended import get_jwt_identity
        current_user_id = int(get_jwt_identity())

        # Prevent admin from deleting themselves
        if user_id == current_user_id:
            return jsonify({"message": "You cannot delete your own account"}), 400

        user = User.query.get(user_id)
        if not user:
            return jsonify({"message": "User not found"}), 404

        username = user.username
        try:
            db.session.delete(user)
            db.session.commit()
        except Exception:
            db.session.rollback()
            return jsonify({"message": "Failed to delete user"}), 500

        log_event(
            event_type="USER_DELETED_BY_ADMIN",
            severity="CRITICAL",
            message=f"User {username} permanently deleted by admin",
            ip_address=request.remote_addr
        )

        return jsonify({"message": f"User {username} deleted successfully"}), 200