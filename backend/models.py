from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
import hashlib
import json

db = SQLAlchemy()


# ==========================================================
# USER MODEL
# ==========================================================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(100), unique=True, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)

    # NEW: track login activity
    last_login = db.Column(db.DateTime(timezone=True), nullable=True)
    login_count = db.Column(db.Integer, default=0)

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )


# ==========================================================
# DEVICE MODEL
# ==========================================================
class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    device_id = db.Column(db.String(100), unique=True, nullable=False, index=True)
    secret_key = db.Column(db.String(200), nullable=False)

    pending_secret_key = db.Column(db.String(200), nullable=True)
    pending_key_version = db.Column(db.Integer, nullable=True)
    key_version = db.Column(db.Integer, default=1)
    status = db.Column(db.String(20), default="ACTIVE")
    key_rotation_required = db.Column(db.Boolean, default=False)

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )


# ==========================================================
# DEVICE NONCE MODEL
# ==========================================================
class DeviceNonce(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(100), nullable=False, index=True)
    nonce = db.Column(db.String(200), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )


# ==========================================================
# SECURITY EVENT MODEL
# ==========================================================
class SecurityEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    event_type = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(20), nullable=False)

    device_id = db.Column(db.String(100), nullable=True)
    user_id = db.Column(db.Integer, nullable=True)
    ip_address = db.Column(db.String(100), nullable=True)
    message = db.Column(db.String(500), nullable=True)

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )


# ==========================================================
# ALERT MODEL
# ==========================================================
class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    alert_type = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(500), nullable=False)

    source_ip = db.Column(db.String(100), nullable=True)
    related_user_id = db.Column(db.Integer, nullable=True)
    related_device_id = db.Column(db.String(100), nullable=True)
    event_count = db.Column(db.Integer, default=1)

    soar_executed = db.Column(db.Boolean, default=False)
    soar_action = db.Column(db.String(100), nullable=True)

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )


# ==========================================================
# BLOCKED IP MODEL
# ==========================================================
class BlockedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), unique=True, nullable=False)
    reason = db.Column(db.String(255))
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )


# ==========================================================
# BLOCKCHAIN LEDGER MODEL
# ==========================================================
class BlockchainBlock(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    device_id = db.Column(db.String(100), nullable=False)
    key_hash = db.Column(db.String(64), nullable=False)
    key_version = db.Column(db.Integer, nullable=False)
    key_status = db.Column(db.String(20), nullable=False)

    previous_hash = db.Column(db.String(64), nullable=False)
    block_hash = db.Column(db.String(64), nullable=False)

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    def compute_hash(self):
        block_string = json.dumps({
            "device_id": self.device_id,
            "key_hash": self.key_hash,
            "key_version": self.key_version,
            "key_status": self.key_status,
            "previous_hash": self.previous_hash
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()