from flask import request, jsonify, Response
from flask_jwt_extended import jwt_required
from datetime import datetime, timedelta, timezone
import os
import base64
import hmac
import hashlib
import secrets
import csv
import io
from datetime import timezone, timedelta

from models import db, Device, DeviceNonce, SecurityEvent, BlockedIP, BlockchainBlock
from security import generate_hmac
from auth import require_role
from logging_engine import log_event
from blockchain_engine import add_block, validate_chain

IST = timezone(timedelta(hours=5, minutes=30))

# -------------------------------------------------------
# Input length constants
# -------------------------------------------------------
MAX_DEVICE_ID_LEN = 100
MAX_SECRET_KEY_LEN = 200
MAX_HMAC_LEN = 64
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200


def _is_valid_hex(s):
    """Returns True only if s is a lowercase hex string of exactly 64 chars."""
    if not isinstance(s, str) or len(s) != MAX_HMAC_LEN:
        return False
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


def register_device_routes(app):

    # =====================================================
    # DEVICE REGISTRATION (ADMIN ONLY)
    # =====================================================
    @app.route("/register-device", methods=["POST"])
    @jwt_required()
    @require_role("admin")
    def register_device():
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"message": "Invalid JSON body"}), 400

        device_id = data.get("device_id", "")
        secret_key = data.get("secret_key", "")

        # SAFE FIX: validate input lengths before hitting the DB
        if not device_id or not secret_key:
            return jsonify({"message": "Device ID and secret key required"}), 400

        if len(device_id) > MAX_DEVICE_ID_LEN:
            return jsonify({"message": f"device_id too long (max {MAX_DEVICE_ID_LEN})"}), 400

        if len(secret_key) > MAX_SECRET_KEY_LEN:
            return jsonify({"message": f"secret_key too long (max {MAX_SECRET_KEY_LEN})"}), 400

        if Device.query.filter_by(device_id=device_id).first():
            return jsonify({"message": "Device already exists"}), 400

        try:
            new_device = Device(
                device_id=device_id,
                secret_key=secret_key,
                status="ACTIVE",
                key_version=1
            )
            db.session.add(new_device)
            db.session.flush()   # get the id before committing

            key_hash = hashlib.sha256(secret_key.encode()).hexdigest()
            add_block(
                device_id=device_id,
                key_hash=key_hash,
                key_version=1,
                key_status="ACTIVE"
            )

            db.session.commit()
        except Exception:
            db.session.rollback()
            return jsonify({"message": "Device registration failed"}), 500

        log_event(
            event_type="DEVICE_REGISTERED",
            severity="INFO",
            message="New device registered successfully",
            device_id=device_id,
            ip_address=request.remote_addr
        )

        return jsonify({"message": "Device registered successfully"}), 201


    # =====================================================
    # LIST DEVICES (ADMIN ONLY)  —  with pagination
    # =====================================================
    @app.route("/list-devices", methods=["GET"])
    @jwt_required()
    @require_role("admin")
    def list_devices():
        # SAFE FIX: .all() on large tables loads everything into memory.
        # Pagination prevents memory exhaustion.
        page = request.args.get("page", 1, type=int)
        per_page = min(
            request.args.get("per_page", DEFAULT_PAGE_SIZE, type=int),
            MAX_PAGE_SIZE
        )

        pagination = Device.query.paginate(page=page, per_page=per_page, error_out=False)

        return jsonify({
            "devices": [
                {
                    "device_id": d.device_id,
                    "key_version": d.key_version,
                    "status": d.status,
                    "created_at": d.created_at.isoformat() if d.created_at else None
                }
                for d in pagination.items
            ],
            "total": pagination.total,
            "page": pagination.page,
            "pages": pagination.pages
        }), 200


    # =====================================================
    # GENERATE CHALLENGE
    # =====================================================
    @app.route("/generate-challenge", methods=["POST"])
    def generate_challenge():
        client_ip = request.remote_addr

        blocked = BlockedIP.query.filter_by(ip_address=client_ip).first()
        if blocked:
            return jsonify({"error": "Your IP has been blocked"}), 403

        data = request.get_json(silent=True)
        if not data or "device_id" not in data:
            return jsonify({"message": "device_id required"}), 400

        device_id = str(data.get("device_id", ""))[:MAX_DEVICE_ID_LEN]

        device = Device.query.filter_by(device_id=device_id).first()

        if not device:
            log_event(
                event_type="INVALID_DEVICE",
                severity="HIGH",
                message="Challenge requested for invalid device",
                device_id=device_id,
                ip_address=client_ip
            )
            return jsonify({"message": "Invalid device"}), 400

        if device.status == "LOCKED":
            return jsonify({"error": "Device is locked due to security policy"}), 403

        if device.status != "ACTIVE":
            return jsonify({"message": "Device is inactive"}), 400

        try:
            DeviceNonce.query.filter_by(device_id=device_id).delete()
            nonce = base64.b64encode(os.urandom(16)).decode()
            new_nonce = DeviceNonce(device_id=device_id, nonce=nonce)
            db.session.add(new_nonce)
            db.session.commit()
        except Exception:
            db.session.rollback()
            return jsonify({"message": "Challenge generation failed"}), 500

        log_event(
            event_type="CHALLENGE_ISSUED",
            severity="INFO",
            message="Challenge nonce generated successfully",
            device_id=device_id,
            ip_address=client_ip
        )

        return jsonify({"nonce": nonce}), 200


    # =====================================================
    # VERIFY RESPONSE
    # =====================================================
    @app.route("/verify-response", methods=["POST"])
    def verify_response():
        client_ip = request.remote_addr

        blocked = BlockedIP.query.filter_by(ip_address=client_ip).first()
        if blocked:
            return jsonify({"error": "Your IP has been blocked"}), 403

        data = request.get_json(silent=True)
        if not data or "device_id" not in data or "hmac" not in data:
            return jsonify({"message": "device_id and hmac required"}), 400

        device_id = str(data.get("device_id", ""))[:MAX_DEVICE_ID_LEN]
        received_hmac = data.get("hmac", "")

        # SAFE FIX: validate that the HMAC is a valid hex string, not just the right length.
        # An attacker could send "0" * 64 which passes the old length check but is obviously
        # not a real HMAC. We now require valid lowercase hex.
        if not _is_valid_hex(received_hmac):
            return jsonify({"message": "Invalid HMAC format"}), 400

        device = Device.query.filter_by(device_id=device_id).first()
        if not device:
            log_event(
                event_type="INVALID_DEVICE",
                severity="HIGH",
                message="Authentication attempt from invalid/inactive device",
                device_id=device_id,
                ip_address=client_ip
            )
            return jsonify({"message": "Invalid device"}), 400

        if device.status == "LOCKED":
            return jsonify({"error": "Device is locked due to security policy"}), 403

        if device.status != "ACTIVE":
            return jsonify({"message": "Invalid device state"}), 400

        nonce_entry = DeviceNonce.query.filter_by(device_id=device_id).first()
        if not nonce_entry:
            log_event(
                event_type="NONCE_REPLAY_ATTEMPT",
                severity="CRITICAL",
                message="Replay attempt detected: No active nonce found",
                device_id=device_id,
                ip_address=client_ip
            )
            return jsonify({"message": "No active challenge"}), 400

        created_at = nonce_entry.created_at
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)

        current_time = datetime.now(timezone.utc)

        if current_time > created_at + timedelta(minutes=2):
            try:
                db.session.delete(nonce_entry)
                db.session.commit()
            except Exception:
                db.session.rollback()

            log_event(
                event_type="CHALLENGE_EXPIRED",
                severity="MEDIUM",
                message="Challenge expired before response received",
                device_id=device_id,
                ip_address=client_ip
            )
            return jsonify({"message": "Challenge expired"}), 401

        # Chain integrity check
        if not validate_chain():
            log_event(
                event_type="BLOCKCHAIN_TAMPER_DETECTED",
                severity="CRITICAL",
                message="Blockchain integrity validation failed during device authentication",
                device_id=device_id,
                ip_address=client_ip
            )
            return jsonify({"error": "Blockchain integrity compromised"}), 500

        latest_block = BlockchainBlock.query.filter_by(
            device_id=device_id
        ).order_by(BlockchainBlock.id.desc()).first()

        if not latest_block:
            return jsonify({"error": "Device not registered in blockchain"}), 403

        current_key_hash = hashlib.sha256(device.secret_key.encode()).hexdigest()
        if current_key_hash != latest_block.key_hash:
            return jsonify({"error": "Key integrity validation failed"}), 403

        if latest_block.key_status != "ACTIVE":
            return jsonify({"error": "Key is not active according to blockchain"}), 403

        expected_hmac_current = generate_hmac(device.secret_key, nonce_entry.nonce)

        expected_hmac_pending = None
        if device.pending_secret_key:
            expected_hmac_pending = generate_hmac(device.pending_secret_key, nonce_entry.nonce)

        # SAFE FIX: delete nonce before comparing, so that even if this
        # request crashes mid-way the nonce cannot be reused.
        try:
            db.session.delete(nonce_entry)
            db.session.commit()
        except Exception:
            db.session.rollback()
            return jsonify({"message": "Authentication error"}), 500

        is_valid = False
        used_pending = False

        if hmac.compare_digest(expected_hmac_current, received_hmac):
            is_valid = True
        elif expected_hmac_pending and hmac.compare_digest(expected_hmac_pending, received_hmac):
            is_valid = True
            used_pending = True

        if is_valid:
            log_event(
                event_type="AUTH_SUCCESS",
                severity="INFO",
                message="Device authenticated successfully",
                device_id=device_id,
                ip_address=client_ip
            )
            return jsonify({
                "message": "Device authenticated successfully",
                "rotation_required": device.key_rotation_required,
                "used_pending_key": used_pending
            }), 200

        else:
            log_event(
                event_type="HMAC_MISMATCH",
                severity="HIGH",
                message="HMAC verification failed (invalid response)",
                device_id=device_id,
                ip_address=client_ip
            )
            return jsonify({"message": "Invalid HMAC"}), 401


    # =====================================================
    # INITIATE KEY ROTATION
    # =====================================================
    @app.route("/rotate-secret", methods=["POST"])
    def rotate_secret():
        client_ip = request.remote_addr

        blocked = BlockedIP.query.filter_by(ip_address=client_ip).first()
        if blocked:
            return jsonify({"error": "Your IP has been blocked"}), 403

        data = request.get_json(silent=True)
        if not data or "device_id" not in data:
            return jsonify({"message": "device_id required"}), 400

        device_id = str(data.get("device_id", ""))[:MAX_DEVICE_ID_LEN]
        device = Device.query.filter_by(device_id=device_id).first()

        if not device:
            return jsonify({"message": "Invalid device"}), 400

        if device.status != "ACTIVE":
            return jsonify({"message": "Device not active"}), 403

        if not device.key_rotation_required:
            return jsonify({"message": "Rotation not required"}), 400

        if not validate_chain():
            return jsonify({"error": "Blockchain integrity compromised"}), 500

        if device.pending_secret_key:
            return jsonify({"message": "Rotation already in progress"}), 400

        try:
            new_secret = secrets.token_hex(32)
            new_version = device.key_version + 1

            device.pending_secret_key = new_secret
            device.pending_key_version = new_version
            db.session.commit()
        except Exception:
            db.session.rollback()
            return jsonify({"message": "Key rotation initiation failed"}), 500

        log_event(
            event_type="KEY_ROTATION_INITIATED",
            severity="HIGH",
            message="Key rotation initiated (pending secret created)",
            device_id=device_id,
            ip_address=client_ip
        )

        return jsonify({
            "rotation_started": True,
            "new_secret": new_secret,
            "new_key_version": new_version
        }), 200


    # =====================================================
    # CONFIRM KEY ROTATION
    # =====================================================
    @app.route("/confirm-rotation", methods=["POST"])
    def confirm_rotation():
        client_ip = request.remote_addr

        blocked = BlockedIP.query.filter_by(ip_address=client_ip).first()
        if blocked:
            return jsonify({"error": "Your IP has been blocked"}), 403

        data = request.get_json(silent=True)
        if not data or "device_id" not in data:
            return jsonify({"message": "device_id required"}), 400

        device_id = str(data.get("device_id", ""))[:MAX_DEVICE_ID_LEN]
        device = Device.query.filter_by(device_id=device_id).first()

        if not device:
            return jsonify({"message": "Invalid device"}), 400

        if not device.pending_secret_key:
            return jsonify({"message": "No pending rotation found"}), 400

        if not validate_chain():
            return jsonify({"error": "Blockchain integrity compromised"}), 500

        try:
            device.secret_key = device.pending_secret_key
            device.key_version = device.pending_key_version

            device.pending_secret_key = None
            device.pending_key_version = None
            device.key_rotation_required = False

            new_hash = hashlib.sha256(device.secret_key.encode()).hexdigest()
            add_block(
                device_id=device_id,
                key_hash=new_hash,
                key_version=device.key_version,
                key_status="ACTIVE"
            )

            db.session.commit()

        except Exception:
            db.session.rollback()
            return jsonify({"error": "Rotation finalization failed"}), 500

        log_event(
            event_type="KEY_ROTATION_COMPLETED",
            severity="CRITICAL",
            message="Key rotation finalized successfully",
            device_id=device_id,
            ip_address=client_ip
        )

        return jsonify({"rotation_completed": True}), 200


    # =====================================================
    # SECURITY EVENTS (ADMIN ONLY) — with pagination
    # =====================================================
    @app.route("/security-events", methods=["GET"])
    @jwt_required()
    @require_role("admin")
    def get_security_events():
        # SAFE FIX: was loading all events with .all() — could be thousands of rows
        page = request.args.get("page", 1, type=int)
        per_page = min(
            request.args.get("per_page", DEFAULT_PAGE_SIZE, type=int),
            MAX_PAGE_SIZE
        )
        severity_filter = request.args.get("severity")
        event_type_filter = request.args.get("event_type")

        query = SecurityEvent.query.order_by(SecurityEvent.created_at.desc())

        if severity_filter:
            query = query.filter(SecurityEvent.severity == severity_filter.upper())

        if event_type_filter:
            query = query.filter(SecurityEvent.event_type == event_type_filter.upper())

        pagination = query.paginate(page=page, per_page=per_page, error_out=False)

        result = []
        for e in pagination.items:
            created_at = e.created_at
            if created_at and created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
            ist_time = created_at.astimezone(IST) if created_at else None

            result.append({
                "id": e.id,
                "event_type": e.event_type,
                "severity": e.severity,
                "device_id": e.device_id,
                "user_id": e.user_id,
                "message": e.message,
                "ip_address": e.ip_address,
                "timestamp_IST": ist_time.strftime("%Y-%m-%d %H:%M:%S") if ist_time else None
            })

        return jsonify({
            "events": result,
            "total": pagination.total,
            "page": pagination.page,
            "pages": pagination.pages
        }), 200
    # =====================================================
    # EXPORT SECURITY EVENTS AS CSV (ADMIN ONLY)
    # =====================================================
    @app.route("/security-events/export", methods=["GET"])
    @jwt_required()
    @require_role("admin")
    def export_security_events():

        IST = timezone(timedelta(hours=5, minutes=30))

        # Optional filters
        severity_filter = request.args.get("severity")
        event_type_filter = request.args.get("event_type")

        query = SecurityEvent.query.order_by(SecurityEvent.created_at.desc())

        if severity_filter:
            query = query.filter(SecurityEvent.severity == severity_filter.upper())
        if event_type_filter:
            query = query.filter(SecurityEvent.event_type == event_type_filter.upper())

        events = query.all()

        # Build CSV in memory
        output = io.StringIO()
        writer = csv.writer(output)

        # Header row
        writer.writerow([
            "ID", "Severity", "Event Type", "Device ID",
            "User ID", "IP Address", "Message", "Timestamp (IST)"
        ])

        # Data rows
        for e in events:
            created_at = e.created_at
            if created_at and created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
            ist_time = created_at.astimezone(IST) if created_at else None

            writer.writerow([
                e.id,
                e.severity,
                e.event_type,
                e.device_id or "",
                e.user_id or "",
                e.ip_address or "",
                e.message or "",
                ist_time.strftime("%Y-%m-%d %H:%M:%S") if ist_time else ""
            ])

        output.seek(0)

        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={
                "Content-Disposition": "attachment; filename=security_events.csv"
            }
        )